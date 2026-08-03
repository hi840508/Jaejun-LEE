// build: 2026-07-31 항목5 미러 라우트 반영 재시작 트리거
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

// ===================== 💬 채팅 첨부 로컬 디스크 저장 =====================
// 예전: 첨부(이미지·영상·3D)를 base64로 메시지 텍스트에 통째 인라인 → 방 열 때마다 전량 재전송(느림).
// 이제: 파일을 서버 로컬 디스크(chat_uploads/)에 1회 저장하고 메시지엔 URL만 담는다 → 로딩 시 썸네일/URL만, 원본은 클릭 시 지연 로드 + 브라우저 캐시.
const CHAT_UPLOAD_DIR = path.join(__dirname, 'chat_uploads');
try { fs.mkdirSync(CHAT_UPLOAD_DIR, { recursive: true }); } catch (e) { console.warn('chat_uploads 생성 실패', e && e.message); }
app.use('/chat-files', express.static(CHAT_UPLOAD_DIR, { maxAge: '365d', immutable: true }));

// ☁️ Cloudflare R2 첨부 오프로드 — r2.config.json(비공개, git 제외) 또는 환경변수 있으면 R2에 저장(무료 egress). 없으면 로컬 디스크.
let _r2 = null;
(function _initR2() {
    try {
        let cfg = null;
        const p = path.join(__dirname, 'r2.config.json');
        if (fs.existsSync(p)) cfg = JSON.parse(fs.readFileSync(p, 'utf8'));
        else if (process.env.R2_ACCESS_KEY_ID) cfg = { accountId: process.env.R2_ACCOUNT_ID, endpoint: process.env.R2_ENDPOINT, accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY, bucket: process.env.R2_BUCKET, publicBase: process.env.R2_PUBLIC_BASE };
        if (!cfg || !cfg.accessKeyId || !cfg.bucket || !cfg.publicBase) return;
        const { S3Client } = require('@aws-sdk/client-s3');
        const client = new S3Client({ region: 'auto', endpoint: cfg.endpoint || ('https://' + cfg.accountId + '.r2.cloudflarestorage.com'), credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey } });
        _r2 = { client, bucket: cfg.bucket, publicBase: String(cfg.publicBase).replace(/\/+$/, '') };
        console.log('☁️ R2 첨부 오프로드 활성화:', _r2.publicBase, '(bucket:', _r2.bucket + ')');
    } catch (e) { console.warn('R2 초기화 실패 → 로컬 디스크 사용:', e && e.message); _r2 = null; }
})();
function _mimeFromExt(ext) {
    const m = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.bmp': 'image/bmp', '.pdf': 'application/pdf', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime', '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.m4a': 'audio/mp4', '.txt': 'text/plain', '.md': 'text/plain', '.html': 'text/html', '.json': 'application/json', '.csv': 'text/csv', '.zip': 'application/zip' };
    return m[String(ext || '').toLowerCase()] || 'application/octet-stream';
}
// 💬 첨부 보존기간 최대 14일 — 초과분 자동 삭제(디스크 무한 누적 방지). 부팅 시 1회 + 6시간마다.
const CHAT_ATTACH_TTL_MS = 14 * 24 * 60 * 60 * 1000;
function cleanupOldChatAttachments() {
    try {
        const now = Date.now();
        let removed = 0, freed = 0;
        for (const f of fs.readdirSync(CHAT_UPLOAD_DIR)) {
            const fp = path.join(CHAT_UPLOAD_DIR, f);
            try {
                const st = fs.statSync(fp);
                if (st.isFile() && (now - st.mtimeMs) > CHAT_ATTACH_TTL_MS) { freed += st.size; fs.rmSync(fp, { force: true }); removed++; }
            } catch (_) {}
        }
        if (removed) console.log(`🧹 채팅 첨부 정리: ${removed}개 삭제(${(freed / 1048576).toFixed(1)}MB) — 14일 초과`);
    } catch (e) { console.warn('첨부 정리 오류', e && e.message); }
}
cleanupOldChatAttachments();
setInterval(cleanupOldChatAttachments, 6 * 60 * 60 * 1000);

// 실제 비대칭 디지털 서명 알고리즘(ECDSA) 
// 🔐 서명 키페어 — 매 부팅 재생성(=재시작마다 서명 불일치, 크론 재시작 시 특히) 방지: 디스크 영속화(gitignore된 signing_keys.json).
let publicKey, privateKey;
(function () {
    const KEY_PATH = path.join(__dirname, 'signing_keys.json');
    try {
        if (fs.existsSync(KEY_PATH)) { const j = JSON.parse(fs.readFileSync(KEY_PATH, 'utf8')); publicKey = j.publicKey; privateKey = j.privateKey; }
    } catch (_) {}
    if (!publicKey || !privateKey) {
        const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
        publicKey = kp.publicKey; privateKey = kp.privateKey;
        try { fs.writeFileSync(KEY_PATH, JSON.stringify({ publicKey, privateKey }), { mode: 0o600 }); } catch (e) { console.warn('서명키 저장 실패', e && e.message); }
    }
})();

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ===================== #10/#11: RAYCloud 외부 공유 링크(실제·14일 만료) + 이메일 발송 =====================
let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch (e) { console.warn("⚠️ nodemailer 미설치 — 이메일 발송 기능을 쓰려면 'npm install nodemailer' 하세요."); }

const SHARE_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14일
function _shareBaseUrl(req) {
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return `${proto}://${host}`;
}
function _escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

// ===================== 🖥 원격 도우미(무설치 exe) 배포 =====================
// agent/ 는 git 미추적 폴더 → git reset --hard 에도 보존(exe·버전 파일 유지). 빌드한 exe를 여기에 두면 배포됨.
const RC_AGENT_DIR = path.join(__dirname, 'agent');
try { fs.mkdirSync(RC_AGENT_DIR, { recursive: true }); } catch (_) {}

// ☁️ 앱 설치파일(APP_Setup.exe/Earth.apk)을 R2로 동기화 → 다운로드 전송비 무료. 크기 같으면 스킵(변경 시에만 업로드).
function _syncAppToR2() {
    if (!_r2) return;
    try {
        const { PutObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
        [{ name: 'APP_Setup.exe', ct: 'application/octet-stream' }, { name: 'Earth.apk', ct: 'application/vnd.android.package-archive' }].forEach(fi => {
            const fp = path.join(RC_AGENT_DIR, fi.name);
            if (!fs.existsSync(fp)) return;
            const size = fs.statSync(fp).size;
            _r2.client.send(new HeadObjectCommand({ Bucket: _r2.bucket, Key: 'app/' + fi.name }))
                .then(h => { if (Number(h.ContentLength) !== size) throw new Error('diff'); })
                .catch(() => { _r2.client.send(new PutObjectCommand({ Bucket: _r2.bucket, Key: 'app/' + fi.name, Body: fs.readFileSync(fp), ContentType: fi.ct })).then(() => console.log('☁️ 앱 파일 R2 업로드:', fi.name, size)).catch(e => console.warn('앱 R2 업로드 실패', fi.name, e && e.message)); });
        });
    } catch (e) { console.warn('_syncAppToR2:', e && e.message); }
}
setTimeout(_syncAppToR2, 8000);

// 🗑 [항목4] R2 리텐션 — 접두사별 보관일 초과분 자동 삭제(용량 무한증가 방지). 앱 파일(app/*)·백업(backup/*)은 별도 관리.
//   att_(채팅 첨부, 소형) = 90일 / big_(대용량 전송, CT 등) = 30일. 대용량은 임시 중계이므로 더 짧게 회수해 10GB 무료 한도 유지.
function _r2RetentionSweepPrefix(prefix, days) {
    if (!_r2) return;
    try {
        const { ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
        const cutoff = Date.now() - (days || 90) * 24 * 60 * 60 * 1000;
        let token, toDel = [];
        const rx = new RegExp('^' + prefix + '(\\d+)_');
        const run = () => _r2.client.send(new ListObjectsV2Command({ Bucket: _r2.bucket, Prefix: prefix, ContinuationToken: token }))
            .then(out => {
                (out.Contents || []).forEach(o => { const m = rx.exec(o.Key || ''); if (m && Number(m[1]) < cutoff) toDel.push({ Key: o.Key }); });
                if (out.IsTruncated) { token = out.NextContinuationToken; return run(); }
                for (let i = 0; i < toDel.length; i += 1000) { _r2.client.send(new DeleteObjectsCommand({ Bucket: _r2.bucket, Delete: { Objects: toDel.slice(i, i + 1000) } })).catch(() => {}); }
                if (toDel.length) console.log('🗑 R2 리텐션 삭제(' + prefix + ', ' + (days || 90) + '일):', toDel.length);
            }).catch(e => console.warn('R2 리텐션 스윕(' + prefix + '):', e && e.message));
        run();
    } catch (e) {}
}
function _r2RetentionSweep() { _r2RetentionSweepPrefix('att_', 90); _r2RetentionSweepPrefix('big_', 30); }
setTimeout(_r2RetentionSweep, 60 * 1000);
setInterval(_r2RetentionSweep, 24 * 60 * 60 * 1000);

// 📊 [항목4] R2 사용량 집계(접두사별 바이트/개수) — 관리자 화면에서 10GB 무료 한도 모니터링. 무료 조회(Class B).
function _r2Usage(cb) {
    if (!_r2) return cb(new Error('R2 미설정'));
    try {
        const { ListObjectsV2Command } = require('@aws-sdk/client-s3');
        const groups = {};
        const bucketOf = (k) => { const m = /^(backup|app|big|att)/.exec(k); return m ? m[1] : 'etc'; };
        let token, total = 0;
        const run = () => _r2.client.send(new ListObjectsV2Command({ Bucket: _r2.bucket, ContinuationToken: token }))
            .then(out => {
                (out.Contents || []).forEach(o => { const g = bucketOf(o.Key || ''); groups[g] = groups[g] || { bytes: 0, count: 0 }; groups[g].bytes += (o.Size || 0); groups[g].count++; total += (o.Size || 0); });
                if (out.IsTruncated) { token = out.NextContinuationToken; return run(); }
                cb(null, { total, freeLimit: 10 * 1024 * 1024 * 1024, groups });
            }).catch(e => cb(e));
        run();
    } catch (e) { cb(e); }
}

// ☁️ R2 CORS — 브라우저가 프리사인 URL로 직접 PUT/GET 가능하게(멀티파트 대용량 업로드용). ETag 노출 필수.
function _r2SetCors() {
    if (!_r2) return;
    try {
        const { PutBucketCorsCommand } = require('@aws-sdk/client-s3');
        _r2.client.send(new PutBucketCorsCommand({ Bucket: _r2.bucket, CORSConfiguration: { CORSRules: [{ AllowedOrigins: ['*'], AllowedMethods: ['GET', 'PUT', 'HEAD'], AllowedHeaders: ['*'], ExposeHeaders: ['ETag'], MaxAgeSeconds: 3600 }] } }))
            .then(() => console.log('☁️ R2 CORS 설정 완료')).catch(e => console.warn('R2 CORS 설정 실패:', e && e.message));
    } catch (e) {}
}
setTimeout(_r2SetCors, 9000);

// ☁️ 대용량 파일 재개가능 전송(멀티파트) — 브라우저가 R2로 직접 업로드(서버 대역폭 0). 끊겨도 이어받기.
app.post('/api/bigfile/start', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const { filename, mime } = req.body || {};
    let ext = path.extname(String(filename || '')).slice(0, 12).replace(/[^.\w]/g, ''); if (!ext) ext = '.bin';
    const key = 'big_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex') + ext;
    const { CreateMultipartUploadCommand } = require('@aws-sdk/client-s3');
    _r2.client.send(new CreateMultipartUploadCommand({ Bucket: _r2.bucket, Key: key, ContentType: mime || 'application/octet-stream' }))
        .then(o => res.json({ success: true, key, uploadId: o.UploadId, partSize: 8 * 1024 * 1024, url: _r2.publicBase + '/' + key }))
        .catch(e => res.status(500).json({ error: e.message }));
});
app.post('/api/bigfile/sign', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const { key, uploadId, partNumber } = req.body || {};
    const { UploadPartCommand } = require('@aws-sdk/client-s3');
    const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
    getSignedUrl(_r2.client, new UploadPartCommand({ Bucket: _r2.bucket, Key: key, UploadId: uploadId, PartNumber: Number(partNumber) }), { expiresIn: 3600 })
        .then(url => res.json({ success: true, url })).catch(e => res.status(500).json({ error: e.message }));
});
app.post('/api/bigfile/list', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const { key, uploadId } = req.body || {};
    const { ListPartsCommand } = require('@aws-sdk/client-s3');
    _r2.client.send(new ListPartsCommand({ Bucket: _r2.bucket, Key: key, UploadId: uploadId }))
        .then(o => res.json({ success: true, parts: (o.Parts || []).map(p => ({ PartNumber: p.PartNumber, ETag: p.ETag, Size: p.Size })) }))
        .catch(e => res.status(500).json({ error: e.message }));
});
app.post('/api/bigfile/complete', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const { key, uploadId, parts } = req.body || {};
    const { CompleteMultipartUploadCommand } = require('@aws-sdk/client-s3');
    const ordered = (parts || []).slice().sort((a, b) => a.PartNumber - b.PartNumber);
    _r2.client.send(new CompleteMultipartUploadCommand({ Bucket: _r2.bucket, Key: key, UploadId: uploadId, MultipartUpload: { Parts: ordered } }))
        .then(() => res.json({ success: true, url: _r2.publicBase + '/' + key })).catch(e => res.status(500).json({ error: e.message }));
});
app.post('/api/bigfile/abort', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    if (!_r2) return res.json({ success: true });
    const { key, uploadId } = req.body || {};
    const { AbortMultipartUploadCommand } = require('@aws-sdk/client-s3');
    _r2.client.send(new AbortMultipartUploadCommand({ Bucket: _r2.bucket, Key: key, UploadId: uploadId })).then(() => res.json({ success: true })).catch(() => res.json({ success: true }));
});
// ============ 📁 2A: 기기 등록 / 목록 (다중기기 + 공유폴더 상태) ============
app.post('/api/devices/register', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const { deviceId, name, platform, hasFolder, folderName } = req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'deviceId 필요' });
    const now = Date.now();
    db.run(`INSERT INTO devices (deviceId, userName, name, platform, hasFolder, folderName, lastSeen, created)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(deviceId) DO UPDATE SET userName=excluded.userName, name=excluded.name, platform=excluded.platform,
              hasFolder=excluded.hasFolder, folderName=excluded.folderName, lastSeen=excluded.lastSeen`,
        [deviceId, me, name || '내 기기', platform || '', hasFolder ? 1 : 0, folderName || '', now, now],
        function (e) {
            if (e) return res.status(500).json({ error: e.message });
            db.all(`SELECT deviceId, name, platform, hasFolder, folderName, lastSeen FROM devices WHERE userName=? ORDER BY lastSeen DESC`, [me],
                (e2, rows) => res.json({ success: true, devices: rows || [] }));
        });
});
app.get('/api/devices', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.all(`SELECT deviceId, name, platform, hasFolder, folderName, lastSeen FROM devices WHERE userName=? ORDER BY lastSeen DESC`, [me],
        (e, rows) => e ? res.status(500).json({ error: e.message }) : res.json({ devices: rows || [] }));
});
app.post('/api/devices/rename', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const { deviceId, name } = req.body || {};
    if (!deviceId || !name) return res.status(400).json({ error: '값 필요' });
    db.run(`UPDATE devices SET name=? WHERE deviceId=? AND userName=?`, [name, deviceId, me],
        (e) => e ? res.status(500).json({ error: e.message }) : res.json({ success: true }));
});
// 📁 2B: 이 기기의 공유폴더 파일 인덱스 보고(전체 교체) — 반투명 합집합 표시용
app.post('/api/devices/files', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const { deviceId, files } = req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'deviceId 필요' });
    const list = Array.isArray(files) ? files.slice(0, 2000) : [];
    db.serialize(() => {
        db.run(`DELETE FROM device_files WHERE deviceId=? AND userName=?`, [deviceId, me]);
        const stmt = db.prepare(`INSERT OR IGNORE INTO device_files (userName,deviceId,fname,size,hash,thumb,mime,updated) VALUES (?,?,?,?,?,?,?,?)`);
        const now = Date.now();
        for (const f of list) {
            if (!f || !f.fname) continue;
            stmt.run([me, deviceId, String(f.fname).slice(0, 300), Number(f.size) || 0,
                String(f.hash || f.fname).slice(0, 300), String(f.thumb || '').slice(0, 90000),
                String(f.mime || '').slice(0, 100), Number(f.mtime) || now]);   // updated = 파일 날짜(mtime) → 날짜 필터/정렬용
        }
        stmt.finalize((e) => {
            db.run(`UPDATE devices SET lastSeen=? WHERE deviceId=? AND userName=?`, [now, deviceId, me]);
            e ? res.status(500).json({ error: e.message }) : res.json({ success: true, count: list.length });
        });
    });
});
// 📁 2B: 내 모든 기기의 파일 합집합(해시로 그룹) — 각 파일이 어느 기기에 있는지
app.get('/api/devices/files', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.all(`SELECT deviceId,fname,size,hash,thumb,mime,updated FROM device_files WHERE userName=?`, [me], (e, rows) => {
        if (e) return res.status(500).json({ error: e.message });
        db.all(`SELECT deviceId,name FROM devices WHERE userName=?`, [me], (e2, devs) => {
            const dname = {}; (devs || []).forEach(d => dname[d.deviceId] = d.name);
            const g = {};
            (rows || []).forEach(r => {
                const k = r.hash || r.fname;
                if (!g[k]) g[k] = { hash: k, fname: r.fname, size: r.size, mime: r.mime, thumb: r.thumb || '', devices: [], updated: r.updated };
                if (r.thumb && !g[k].thumb) g[k].thumb = r.thumb;
                if (g[k].devices.indexOf(r.deviceId) < 0) g[k].devices.push(r.deviceId);
                if (r.updated > g[k].updated) g[k].updated = r.updated;
            });
            const files = Object.keys(g).map(k => g[k]).sort((a, b) => b.updated - a.updated);
            res.json({ files, deviceNames: dname });
        });
    });
});
// 📁 삭제: 내 계정의 모든 기기 인덱스에서 해당 파일 제거(삭제한 파일이 다른 기기에 반투명으로 남지 않게)
app.post('/api/devices/files/delete', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const { hash, fname, deviceId } = req.body || {};
    if (!hash && !fname) return res.status(400).json({ error: 'hash/fname 필요' });
    // 삭제한 그 기기의 인덱스에서만 제거(다른 기기가 같은 파일을 갖고 있으면 그 기기 것은 유지)
    const cond = hash ? 'hash=?' : 'fname=?';
    const params = [me, hash || fname];
    let q = `DELETE FROM device_files WHERE userName=? AND ${cond}`;
    if (deviceId) { q += ' AND deviceId=?'; params.push(deviceId); }
    db.run(q, params, (e) => e ? res.status(500).json({ error: e.message }) : res.json({ success: true }));
});
app.get('/download/RAY_RemoteAgent.exe', (req, res) => {
    const f = path.join(RC_AGENT_DIR, 'RAY_RemoteAgent.exe');
    if (!fs.existsSync(f)) return res.status(404).send('agent not published yet');
    res.download(f, 'RAY_RemoteAgent.exe');
});
// 📱 PWA(모바일 홈 화면 앱 설치) — manifest / service worker / 아이콘
app.get('/manifest.webmanifest', (req, res) => {
    res.type('application/manifest+json').send(JSON.stringify({
        name: 'Earth', short_name: 'Earth', start_url: '/', scope: '/',
        display: 'standalone', background_color: '#0b0b0f', theme_color: '#111111',
        icons: [
            { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
            { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
            { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
            { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }
        ]
    }));
});
app.get('/icon-192.png', (req, res) => { const f = path.join(__dirname, 'icon-192.png'); if (fs.existsSync(f)) res.type('image/png').send(fs.readFileSync(f)); else res.status(404).end(); });
app.get('/icon-512.png', (req, res) => { const f = path.join(__dirname, 'icon-512.png'); if (fs.existsSync(f)) res.type('image/png').send(fs.readFileSync(f)); else res.status(404).end(); });
// 🩻🧊 [항목3] cornerstone(DICOM)·Three.js(3D) 라이브러리 같은 출처 프록시 — 브라우저 교차출처 웹워커 제약 회피.
//   R2 직접 로드는 교차출처라 워커를 다시 깨뜨리므로 불가. 대신 ① 디스크 영속(lib_cache/, 재시작·unpkg 장애에도 유지)
//   ② 버전 고정 URL이므로 immutable 1년 캐시 → 클라이언트가 최초 1회만 받고 재방문엔 0바이트 → EC2 egress 실질 제거.
const _csLibCache = {};
const LIB_CACHE_DIR = path.join(__dirname, 'lib_cache');   // git 미추적(reset --hard에도 보존)
try { fs.mkdirSync(LIB_CACHE_DIR, { recursive: true }); } catch (_) {}
async function _serveLib(res, name, url) {
    try {
        if (!_csLibCache[url]) {
            const disk = path.join(LIB_CACHE_DIR, name);
            if (fs.existsSync(disk)) {
                _csLibCache[url] = fs.readFileSync(disk);
            } else {
                const r = await fetch(url); if (!r.ok) throw new Error('upstream ' + r.status);
                _csLibCache[url] = Buffer.from(await r.arrayBuffer());
                try { fs.writeFileSync(disk, _csLibCache[url]); } catch (_) {}
            }
        }
        res.type('application/javascript').set('Cache-Control', 'public, max-age=31536000, immutable').send(_csLibCache[url]);
    } catch (e) { res.status(502).send('// lib fetch fail: ' + (e.message || e)); }
}
const _CS_LIBS = {
    'cornerstone.min.js': 'https://unpkg.com/cornerstone-core@2.3.0/dist/cornerstone.min.js',
    'dicomParser.min.js': 'https://unpkg.com/dicom-parser@1.8.13/dist/dicomParser.min.js',
    'wado.bundle.min.js': 'https://unpkg.com/cornerstone-wado-image-loader@4.1.5/dist/cornerstoneWADOImageLoader.bundle.min.js'
};
app.get('/lib/cs/:name', (req, res) => {
    const url = _CS_LIBS[req.params.name]; if (!url) return res.status(404).end();
    _serveLib(res, req.params.name, url);
});
const _THREE_LIBS = {
    'three.min.js': 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js',
    'PLYLoader.js': 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/PLYLoader.js',
    'STLLoader.js': 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/STLLoader.js',
    'OBJLoader.js': 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/loaders/OBJLoader.js',
    'OrbitControls.js': 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js'
};
app.get('/lib/three/:name', (req, res) => {
    const url = _THREE_LIBS[req.params.name]; if (!url) return res.status(404).end();
    _serveLib(res, req.params.name, url);
});
app.get('/sw.js', (req, res) => {
    res.type('application/javascript').send(
        "self.addEventListener('install',e=>self.skipWaiting());\n" +
        "self.addEventListener('activate',e=>self.clients.claim());\n" +
        "self.addEventListener('fetch',function(e){ /* 네트워크 패스스루 — 설치 가능 조건 충족용 */ });\n" +
        "self.addEventListener('push',function(e){\n" +
        "  var d={}; try{ d=e.data.json(); }catch(_){ try{ d={title:'Earth',body:e.data&&e.data.text()}; }catch(__){ d={title:'Earth'}; } }\n" +
        "  var title=d.title||'Earth', body=d.body||'';\n" +
        "  var opts={ body:body, icon:'/icon-192.png', badge:'/icon-192.png', data:d.data||{}, tag:(d.data&&d.data.roomId)||'earth', renotify:true, requireInteraction:true, silent:false, vibrate:[300,120,300,120,300] };\n" +
        "  e.waitUntil((async function(){\n" +
        "    var cs=await self.clients.matchAll({type:'window',includeUncontrolled:true});\n" +
        "    var focused=cs.some(function(c){ return c.focused || c.visibilityState==='visible'; });\n" +
        "    if(focused){ for(var i=0;i<cs.length;i++){ try{ cs[i].postMessage({type:'earth_incoming',data:d.data||{}}); }catch(_){} } return; }\n" +   // 앱이 켜져있으면 시스템 알림 생략(앱 내부에서 처리)
        "    await self.registration.showNotification(title, opts);\n" +
        "    if(typeof d.badge==='number'){ try{ if(self.navigator&&self.navigator.setAppBadge) await self.navigator.setAppBadge(d.badge); }catch(_){} }\n" +
        "  })());\n" +
        "});\n" +
        "self.addEventListener('notificationclick',function(e){\n" +
        "  e.notification.close();\n" +
        "  var rid=e.notification.data&&e.notification.data.roomId;\n" +
        "  e.waitUntil((async function(){\n" +
        "    var all=await self.clients.matchAll({type:'window',includeUncontrolled:true});\n" +
        "    for(var i=0;i<all.length;i++){ var c=all[i]; try{ c.postMessage({type:'earth_open_room',roomId:rid}); }catch(_){} if('focus' in c) return c.focus(); }\n" +
        "    if(self.clients.openWindow) return self.clients.openWindow('/?openroom='+encodeURIComponent(rid||''));\n" +
        "  })());\n" +
        "});\n" +
        "self.addEventListener('pushsubscriptionchange',function(e){\n" +
        "  e.waitUntil((async function(){\n" +
        "    try{\n" +
        "      var old=e.oldSubscription?e.oldSubscription.endpoint:null;\n" +
        "      var vr=await fetch('/api/push/vapid'); var vj=await vr.json(); var key=vj.publicKey;\n" +
        "      function u8(b){ var p='='.repeat((4-b.length%4)%4); var s=(b+p).replace(/-/g,'+').replace(/_/g,'/'); var r=atob(s); var a=new Uint8Array(r.length); for(var i=0;i<r.length;i++)a[i]=r.charCodeAt(i); return a; }\n" +
        "      var sub=await self.registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:u8(key)});\n" +
        "      await fetch('/api/push/resubscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldEndpoint:old,sub:sub})});\n" +
        "    }catch(_){}\n" +
        "  })());\n" +
        "});\n"
    );
});
app.get('/icon.svg', (req, res) => {
    res.type('image/svg+xml').send(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">' +
        '<rect width="512" height="512" rx="104" fill="#111111"/>' +
        '<circle cx="256" cy="256" r="150" fill="none" stroke="#ffffff" stroke-width="18"/>' +
        '<path d="M106 256 h300 M256 106 v300" stroke="#ffffff" stroke-width="12" opacity="0.55"/>' +
        '<path d="M256 106 C150 190 150 322 256 406 C362 322 362 190 256 106 Z" fill="none" stroke="#ffffff" stroke-width="12" opacity="0.85"/>' +
        '</svg>'
    );
});
// 🖥 서버 내장 설치형 PC 앱(Electron) 인스톨러 — agent/ 폴더에 두면 배포됨(git 미추적, reset 보존)
app.get('/download/APP_Setup.exe', (req, res) => {
    // ☁️ R2 설정 시 R2 공개 URL로 리다이렉트(다운로드 전송비 무료). 없으면 로컬 서빙.
    if (_r2) return res.redirect(302, _r2.publicBase + '/app/APP_Setup.exe');
    const f = path.join(RC_AGENT_DIR, 'APP_Setup.exe');
    if (!fs.existsSync(f)) return res.status(404).send('app not published yet');
    res.download(f, 'APP_Setup.exe');
});
// 📱 Android APK(사이드로드) — agent/Earth.apk 에 두면 배포됨. '알 수 없는 앱 허용' 후 설치.
app.get('/download/Earth.apk', (req, res) => {
    if (_r2) return res.redirect(302, _r2.publicBase + '/app/Earth.apk');
    const f = path.join(RC_AGENT_DIR, 'Earth.apk');
    if (!fs.existsSync(f)) return res.status(404).send('apk not published yet');
    res.type('application/vnd.android.package-archive');
    res.download(f, 'Earth.apk');
});
// TWA(APK) 도메인 검증용 — PWABuilder/Bubblewrap이 준 assetlinks.json 을 agent/assetlinks.json 로 올리면 제공됨
app.get('/.well-known/assetlinks.json', (req, res) => {
    const f = path.join(RC_AGENT_DIR, 'assetlinks.json');
    if (!fs.existsSync(f)) return res.status(404).json([]);
    res.type('application/json').send(fs.readFileSync(f, 'utf8'));
});

// ===================== 🔔 웹 푸시 알림(카톡식) =====================
let webpush = null, VAPID_PUB = '';
const pushBadge = new Map();   // userName -> 미확인 알림 수(앱 아이콘 뱃지)
try {
    webpush = require('web-push');
    const vp = path.join(RC_AGENT_DIR, 'vapid.json');
    let keys;
    if (fs.existsSync(vp)) keys = JSON.parse(fs.readFileSync(vp, 'utf8'));
    else { keys = webpush.generateVAPIDKeys(); fs.writeFileSync(vp, JSON.stringify(keys)); }
    VAPID_PUB = keys.publicKey;
    webpush.setVapidDetails('mailto:admin@rayaox.com', keys.publicKey, keys.privateKey);
    console.log('🔔 web-push 준비 완료');
} catch (e) { console.warn('⚠️ web-push 비활성:', e && e.message); }

app.get('/api/push/vapid', (req, res) => res.json({ publicKey: VAPID_PUB }));
app.post('/api/push/subscribe', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const sub = req.body && req.body.sub;
    if (!sub || !sub.endpoint) return res.status(400).json({ error: 'no sub' });
    db.run(`INSERT OR REPLACE INTO push_subs (endpoint, userName, sub, created) VALUES (?, ?, ?, ?)`,
        [sub.endpoint, me, JSON.stringify(sub), new Date().toISOString()], () => res.json({ ok: true }));
});
app.post('/api/push/unsubscribe', (req, res) => {
    const ep = req.body && req.body.endpoint; if (!ep) return res.json({ ok: true });
    db.run(`DELETE FROM push_subs WHERE endpoint = ?`, [ep], () => res.json({ ok: true }));
});
// 구독 회전(pushsubscriptionchange) 시 SW가 인증 없이 호출 — 옛 endpoint로 사용자 매핑해 교체
app.post('/api/push/resubscribe', (req, res) => {
    const oldEp = req.body && req.body.oldEndpoint;
    const sub = req.body && req.body.sub;
    if (!sub || !sub.endpoint || !oldEp) return res.json({ ok: false });
    db.get(`SELECT userName FROM push_subs WHERE endpoint = ?`, [oldEp], (e, r) => {
        if (!r || !r.userName) return res.json({ ok: false });
        db.run(`INSERT OR REPLACE INTO push_subs (endpoint, userName, sub, created) VALUES (?, ?, ?, ?)`,
            [sub.endpoint, r.userName, JSON.stringify(sub), new Date().toISOString()],
            () => db.run(`DELETE FROM push_subs WHERE endpoint = ?`, [oldEp], () => res.json({ ok: true })));
    });
});
app.post('/api/push/clear-badge', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    pushBadge.set(me, 0); res.json({ ok: true });
});
// 특정 사용자에게 푸시(오프라인일 때만 호출). title/body/data 전달 + 뱃지 증가.
function sendPushToUser(name, payload) {
    if (!webpush || !name) return;
    const badge = (pushBadge.get(name) || 0) + 1; pushBadge.set(name, badge);
    const body = JSON.stringify(Object.assign({ badge: badge }, payload));
    db.all(`SELECT endpoint, sub FROM push_subs WHERE userName = ?`, [name], (e, rows) => {
        (rows || []).forEach(r => {
            let sub; try { sub = JSON.parse(r.sub); } catch (_) { return; }
            // urgency:high + TTL → 절전(Doze) 상태에서도 즉시 깨워 전달(카톡식). 미전달 시 하루까지 재시도.
            webpush.sendNotification(sub, body, { urgency: 'high', TTL: 86400 }).catch(err => {
                if (err && (err.statusCode === 404 || err.statusCode === 410)) db.run(`DELETE FROM push_subs WHERE endpoint = ?`, [r.endpoint]);
            });
        });
    });
}
// 사용자가 현재 접속(온라인) 중인지 — 개인 룸에 소켓이 있으면 온라인
function _isUserOnline(name) {
    try { const room = io.sockets.adapter.rooms.get('user:' + name); return !!(room && room.size > 0); } catch (_) { return false; }
}
// 푸시 미리보기 문구(내부 마커는 알림 제외). 반환 ''면 푸시 안 보냄.
function _pushPreview(msg) {
    if (!msg) return '';
    if (/^\[(PRESENCE|HS|STATE|REQSTATE|REMOTE_ACCEPT|RX_DOC)/.test(msg)) return '';   // 내부/시스템 마커
    if (msg.indexOf('[FILE_ATTACH]') === 0) return '📎 파일을 보냈습니다';
    if (msg.indexOf('[VIDEO_INVITE]') === 0) return '📹 화상 통화 요청';
    if (msg.indexOf('[REMOTE_REQUEST]') === 0) return '🖥 원격제어 요청';
    if (msg.indexOf('[TRANSFER]') === 0) return '💸 송금 알림';
    if (msg.indexOf('[ORDER_') === 0 || msg.indexOf('[ITEM_SALE]') === 0 || msg.indexOf('[SETTLE]') === 0) return '🛒 주문 알림';
    return msg.length > 80 ? msg.slice(0, 80) + '…' : msg;
}
app.get('/api/rc/version', (req, res) => {
    let v = '0'; try { v = fs.readFileSync(path.join(RC_AGENT_DIR, 'version.txt'), 'utf8').trim(); } catch (_) {}
    res.json({ version: v, url: '/download/RAY_RemoteAgent.exe', exists: fs.existsSync(path.join(RC_AGENT_DIR, 'RAY_RemoteAgent.exe')), app: fs.existsSync(path.join(RC_AGENT_DIR, 'APP_Setup.exe')), appUrl: '/download/APP_Setup.exe', apk: fs.existsSync(path.join(RC_AGENT_DIR, 'Earth.apk')), apkUrl: '/download/Earth.apk' });
});
// 개인화 원클릭 설치 배치 — 로그인 필요. exe 자동 다운로드 + 페어링(장기 기기 토큰) + 자동시작.
app.post('/api/rc/installer', (req, res) => {
    const t = req.headers['x-auth-token'] || (req.body && req.body._token);
    const s = t && SESSIONS.get(String(t));
    if (!s) return res.status(401).json({ error: '로그인이 필요합니다.' });
    const name = s.name;
    const agentToken = issueToken(name);   // 브라우저 로그아웃과 무관한 장기 기기 토큰
    const base = _shareBaseUrl(req);
    const safeName = String(name).replace(/["\r\n]/g, '');
    const L = [
        '@echo off',
        'chcp 65001 >nul',
        'set "DIR=%LOCALAPPDATA%\\RAYRemoteAgent"',
        'if not exist "%DIR%" mkdir "%DIR%"',
        'echo RAY 원격 도우미를 내려받는 중...',
        'powershell -NoProfile -Command "try{ Invoke-WebRequest -Uri \'' + base + '/download/RAY_RemoteAgent.exe\' -OutFile \'%DIR%\\RAY_RemoteAgent.exe\' -UseBasicParsing }catch{ $c=0; try{ $c=[int]$_.Exception.Response.StatusCode.value__ }catch{}; if($c -eq 404){ exit 2 } else { exit 1 } }"',
        'if errorlevel 2 ( echo [안내] 서버에 원격 도우미가 아직 배포되지 않았습니다. 관리자에게 도우미 배포(원격도우미_빌드배포.bat)를 요청하세요. & pause & exit /b 2 )',
        'if errorlevel 1 ( echo [실패] 다운로드 오류. 인터넷/방화벽 확인 후 다시 실행하세요. & pause & exit /b 1 )',
        'echo 계정에 연결(페어링) 중...',
        '"%DIR%\\RAY_RemoteAgent.exe" pair ' + agentToken + ' "' + safeName + '"',
        'echo 원격 대기 시작(자동시작 등록됨)...',
        'start "" "%DIR%\\RAY_RemoteAgent.exe"',
        'echo.',
        'echo [완료] 이제 채팅에서 원격 지원을 수락하면 이 PC를 제어할 수 있습니다.',
        'timeout /t 4 >nul'
    ];
    res.json({ ok: true, filename: 'RAY원격도우미_설치.bat', bat: L.join('\r\n') });
});

// 링크 생성: 토큰 발급 + payload 저장 + 14일 만료. 실제 접속 가능한 URL 반환
app.post('/api/share/create', (req, res) => {
    const payload = req.body || {};
    const token = crypto.randomBytes(9).toString('base64url'); // 12자 내외 URL-safe 토큰
    const now = Date.now();
    const expiresAt = now + SHARE_TTL_MS;
    db.run(`INSERT INTO share_links (token, payload, createdAt, expiresAt) VALUES (?, ?, ?, ?)`,
        [token, JSON.stringify(payload), now, expiresAt], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, token, url: `${_shareBaseUrl(req)}/share/${token}`, expiresAt });
        });
});

// 링크 접속: 만료 검사 후 공유 안내 페이지 표시
app.get('/share/:token', (req, res) => {
    db.get(`SELECT payload, expiresAt FROM share_links WHERE token = ?`, [req.params.token], (err, row) => {
        if (err) return res.status(500).send('서버 오류');
        if (!row) return res.status(404).send('<meta charset="utf-8"><div style="font-family:system-ui;text-align:center;margin-top:80px;color:#374151">존재하지 않는 공유 링크입니다.</div>');
        if (Date.now() > Number(row.expiresAt || 0)) {
            return res.status(410).send('<meta charset="utf-8"><div style="font-family:system-ui;text-align:center;margin-top:80px;color:#b91c1c">⛔ 만료된 링크입니다. (유효기간 14일 경과)</div>');
        }
        let p = {}; try { p = JSON.parse(row.payload || '{}'); } catch (e) {}
        const exp = new Date(Number(row.expiresAt)).toLocaleString('ko-KR');
        const itemsHtml = (Array.isArray(p.items) ? p.items : [])
            .map(it => `<li>${_escapeHtml(it.name)} <span style="color:#9ca3af">(${_escapeHtml(it.modality||'')})</span></li>`).join('') || '<li style="color:#9ca3af">목록 없음</li>';
        res.send(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RAYCloud 공유</title></head>
<body style="font-family:system-ui,'Pretendard',sans-serif;background:#f3f4f6;margin:0;padding:24px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:24px;">
    <div style="font-size:18px;font-weight:800;color:#1f2937;margin-bottom:6px;">${_escapeHtml(p.title || 'RAYCloud 공유 데이터')}</div>
    <div style="font-size:13px;color:#6b7280;margin-bottom:16px;">보낸 사람: ${_escapeHtml(p.by || '-')}${p.patient ? ' · 환자: ' + _escapeHtml(p.patient) : ''}</div>
    <div style="font-size:13px;color:#374151;font-weight:700;margin-bottom:6px;">공유 항목</div>
    <ul style="font-size:13px;color:#374151;line-height:1.7;margin:0 0 16px 18px;padding:0;">${itemsHtml}</ul>
    <div style="font-size:12px;color:#9ca3af;border-top:1px solid #eee;padding-top:12px;">유효기간: ${exp} 까지</div>
  </div>
</body></html>`);
    });
});

// #11: 첨부 없이 동일한 링크를 이메일로 전송. 발신은 사용자가 입력한 본인 이메일 계정으로.
app.post('/api/share/email', async (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // 🔐 로그인 필수(무인증 메일 발송 오용 차단)
    const { to, link, senderEmail, senderPass, host, port } = req.body || {};
    if (!to || !link) return res.status(400).json({ error: '받는 사람/링크 누락' });
    if (!senderEmail || !senderPass) return res.status(400).json({ error: '발신 계정(본인 이메일/앱 비밀번호)을 입력하세요' });
    if (!nodemailer) return res.status(500).json({ error: "서버에 nodemailer 미설치 ('npm install nodemailer' 후 재시작)" });
    try {
        const smtpHost = host || 'smtp.gmail.com';
        const smtpPort = Number(port) || 465;
        const transporter = nodemailer.createTransport({
            host: smtpHost, port: smtpPort, secure: smtpPort === 465,
            auth: { user: senderEmail, pass: senderPass }
        });
        await transporter.sendMail({
            from: senderEmail,
            to,
            subject: '[RAYCloud] 공유 링크가 도착했습니다',
            text: `RAYCloud에서 데이터를 공유했습니다.\n\n아래 링크로 확인하세요 (유효기간 14일):\n${link}\n`,
            html: `<div style="font-family:system-ui,sans-serif;font-size:14px;color:#374151;line-height:1.6">
                <p>RAYCloud에서 데이터를 공유했습니다.</p>
                <p>아래 링크로 확인하세요. <b>유효기간 14일</b></p>
                <p><a href="${_escapeHtml(link)}" style="color:#2563eb">${_escapeHtml(link)}</a></p></div>`
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: (e && e.message) || '메일 발송 실패 (계정/앱 비밀번호 확인)' });
    }
});
// ============================================================================================

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, maxHttpBufferSize: 300 * 1024 * 1024 }); // 🚀 [v8+] 대형 3D/첨부 번들 지원 (300MB)
const PORT = 4000;

// 🚀 [서버 크래시 해결] 권한 충돌이 없는 안전한 현재 폴더 경로 사용
// .gitignore에 *.sqlite가 등록되어 있으므로 git pull을 해도 데이터가 보존됩니다.
const DB_PATH = path.join(__dirname, 'earth_database_master.sqlite');
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error("데이터베이스 연결 실패:", err);
    else console.log("데이터베이스 원장 연결 성공");
});

function initTables() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, realname TEXT, bank TEXT, account TEXT, balance INTEGER, profilePic TEXT, phone TEXT, email TEXT, shipping_address TEXT, reset_otp TEXT, reset_otp_expiry INTEGER, reset_otp_used INTEGER DEFAULT 0, force_pwd_change INTEGER DEFAULT 0)`);
        db.run(`CREATE TABLE IF NOT EXISTS friends (userName TEXT, friendName TEXT, UNIQUE(userName, friendName))`);
        db.run(`CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, name TEXT, owner TEXT, logo TEXT, status TEXT DEFAULT 'active', background TEXT, description TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, storeId TEXT, type TEXT, name TEXT, description TEXT, price_stream INTEGER DEFAULT 0, price_original INTEGER DEFAULT 0, stream_time INTEGER DEFAULT 0, stream_unit TEXT DEFAULT 'd', seller TEXT, thumbnail TEXT, encryptedPayload TEXT, compression_ratio INTEGER DEFAULT 0, block_hash TEXT, ecc_signature TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productId TEXT, productName TEXT, amount INTEGER, purchaseType TEXT, rawDate TEXT, date TEXT, refunded INTEGER DEFAULT 0)`);
        db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, senderPic TEXT, message TEXT, date TEXT)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_chats_roomId ON chats(roomId)`, () => {});   // ⚡ 채팅 히스토리·활성방 조회 가속
        db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, secretKey TEXT, eccSignature TEXT, is_used INTEGER, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT, rawDate TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, sender_name TEXT, amount INTEGER, status TEXT, date TEXT, rawDate TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, amount INTEGER, status TEXT, date TEXT, rawDate TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, targetStore TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS refund_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, txId INTEGER, buyer TEXT, seller TEXT, productId TEXT, productName TEXT, amount INTEGER, status TEXT DEFAULT 'pending', reason TEXT, request_date TEXT, decision_date TEXT)`);

        // 🚀 [v6] 상품 주문 양식 + 보류 결제 (판매자 승인 필요)
        // status: 'pending' (작성 완료, 판매자 승인 대기) | 'approved' (결제 완료) | 'rejected' (거절) | 'cancelled' (구매자 취소)
        db.run(`CREATE TABLE IF NOT EXISTS product_orders (id INTEGER PRIMARY KEY AUTOINCREMENT, productId TEXT, buyer TEXT, seller TEXT, txId INTEGER, bundle_html TEXT, memo TEXT, form_data TEXT, pdf_filled_data TEXT, buyer_info TEXT, status TEXT DEFAULT 'approved', amount INTEGER DEFAULT 0, created_at TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS cloud_storage (name TEXT PRIMARY KEY, purchasedBytes INTEGER DEFAULT 0, usedBytes INTEGER DEFAULT 0)`);

        // #10: RAYCloud 외부 공유 링크 (실제 토큰, 14일 만료)
        db.run(`CREATE TABLE IF NOT EXISTS share_links (token TEXT PRIMARY KEY, payload TEXT, createdAt INTEGER, expiresAt INTEGER)`);
        // 🔒 통합 뷰어 DRM — 복호 키를 서버 보관, 로그인+바인딩+만료 통과 시에만 전달
        db.run(`CREATE TABLE IF NOT EXISTS viewer_files (fileId TEXT PRIMARY KEY, k TEXT, expiry INTEGER DEFAULT 0, creator TEXT, title TEXT, boundUser TEXT, firstOpenedAt INTEGER, createdAt INTEGER)`);
        db.run(`CREATE TABLE IF NOT EXISTS viewer_opens (id INTEGER PRIMARY KEY AUTOINCREMENT, fileId TEXT, userName TEXT, at INTEGER, ok INTEGER, reason TEXT)`);

        // 🔒💰 전송 파일 잠금(선택) — 금액(price>0: 수신자가 Earth 잔액으로 결제해야 열림)/암호(pwHash) 설정.
        //   둘 다 미설정이면 잠금 미사용(기존 공개 전송과 동일). 실제 R2 URL은 서버에만 보관, 잠금 해제 성공 시에만 전달.
        db.run(`CREATE TABLE IF NOT EXISTS locked_files (token TEXT PRIMARY KEY, owner TEXT, fileName TEXT, url TEXT, mime TEXT, size INTEGER, price INTEGER DEFAULT 0, pwHash TEXT DEFAULT '', createdAt INTEGER)`);
        db.run(`CREATE TABLE IF NOT EXISTS locked_file_unlocks (token TEXT, userName TEXT, at INTEGER, paid INTEGER DEFAULT 0, UNIQUE(token, userName))`);

        // ☁️ [항목5] 로컬 공유폴더 R2 미러 백업(유료 옵션) — 원하는 사용자만 cloud_storage 할당량으로 결제해 사용.
        //   mirror_files: 사용자별 미러된 파일 목록(rpath=공유폴더 상대경로). mirror_prefs: 사용자별 on/off.
        db.run(`CREATE TABLE IF NOT EXISTS mirror_files (userName TEXT, rpath TEXT, key TEXT, size INTEGER DEFAULT 0, mime TEXT, mtime INTEGER, PRIMARY KEY(userName, rpath))`);
        db.run(`CREATE TABLE IF NOT EXISTS mirror_prefs (userName TEXT PRIMARY KEY, enabled INTEGER DEFAULT 0)`);

        // 🔗 [비회원 외부 공유] QR+웹링크로 Earth 미가입 고객에게 파일 전달 → 랜딩페이지에서 가입안내 + 공유폴더 다운로드
        db.run(`CREATE TABLE IF NOT EXISTS guest_shares (token TEXT PRIMARY KEY, owner TEXT, fileName TEXT, url TEXT, mime TEXT, size INTEGER, createdAt INTEGER, expiresAt INTEGER, downloads INTEGER DEFAULT 0)`);

        // 🚀 [v6] 구매로 자동 생성된 대화방 메타 (브랜드명 + 최신 상품명 + 양측 표시 동기화)
        // type: 'order' (구매 후 자동 생성, 한쪽이 leave 시 양측 종료) | 'normal' (수동 친구 추가)
        db.run(`CREATE TABLE IF NOT EXISTS chat_rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT UNIQUE, type TEXT DEFAULT 'normal', buyer TEXT, seller TEXT, storeId TEXT, storeName TEXT, lastProductId TEXT, lastProductName TEXT, ended INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT)`);

        // 🚀 [v7p3] 상품 리뷰 (별점 + 텍스트). 한 구매자가 한 상품에 1회 작성 가능
        db.run(`CREATE TABLE IF NOT EXISTS product_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, productId TEXT, buyer TEXT, seller TEXT, rating INTEGER, review_text TEXT, skipped INTEGER DEFAULT 0, created_at TEXT)`);

        // 🚀 기존 DB 호환을 위한 마이그레이션 (컬럼 추가; 이미 있으면 에러 무시)
        db.run(`ALTER TABLE stores ADD COLUMN background TEXT`, () => {});
        db.run(`ALTER TABLE stores ADD COLUMN description TEXT`, () => {});
        // 🚀 [v6] 상점 카테고리 (브랜드 정체성)
        db.run(`ALTER TABLE stores ADD COLUMN category TEXT DEFAULT 'general'`, () => {});
        // 🧾 세금계산서용: 상점(공급자) 구분(business/individual) + 번호(사업자등록번호/주민등록번호)
        db.run(`ALTER TABLE stores ADD COLUMN bizType TEXT DEFAULT 'business'`, () => {});
        db.run(`ALTER TABLE stores ADD COLUMN bizNo TEXT`, () => {});
        // 💰 [에스크로] Admin 통합관리 상점 플래그: 1이면 이 상점 판매대금은 Admin(hi840508)이 보관→정산으로 지급
        db.run(`ALTER TABLE stores ADD COLUMN admin_managed INTEGER DEFAULT 0`, () => {});
        // 🦷 [기공소] 보철 품목/수가 config(JSON) — 상세 의뢰서의 취급 품목·수가. 캡처: 분류/보철명/수가/폰틱수가, 탭(일반보철·임플란트/덴처/교정)
        db.run(`ALTER TABLE stores ADD COLUMN rx_items TEXT`, () => {});
        db.run(`ALTER TABLE products ADD COLUMN rx_form INTEGER DEFAULT 0`, () => {});   // 1=기공소 의뢰서 작성용 기본 상품(가격 미정)
        // 🚀 [v6] order_orders 컬럼 추가 (구버전 DB 호환)
        db.run(`ALTER TABLE product_orders ADD COLUMN pdf_filled_data TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN buyer_info TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN status TEXT DEFAULT 'approved'`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN tracking TEXT`, () => {});   // 🚚 배송 송장번호(선택)
        db.run(`ALTER TABLE product_orders ADD COLUMN courier TEXT`, () => {});    // 🚚 택배사 코드
        db.run(`ALTER TABLE product_orders ADD COLUMN amount INTEGER DEFAULT 0`, () => {});
        // 💰 [에스크로] 배송완료 시각(자동확정 3일 기준) · 구매확정 시각 · Admin 보관금액 · 정산완료 여부
        db.run(`ALTER TABLE product_orders ADD COLUMN delivered_at TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN confirmed_at TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN escrow_held INTEGER DEFAULT 0`, () => {});   // Admin이 이 주문건으로 보관중인 금액(승인 시 구매자→Admin)
        db.run(`ALTER TABLE product_orders ADD COLUMN settled INTEGER DEFAULT 0`, () => {});       // 1이면 정산(상점 지급) 완료
        db.run(`ALTER TABLE product_orders ADD COLUMN settled_at TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN settle_month TEXT`, () => {});               // 정산 귀속월(YYYY-MM)
        db.run(`ALTER TABLE transactions ADD COLUMN refunded INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN business_type TEXT DEFAULT 'individual'`, () => {});
        // 🚀 [v8+] 자격증 + 승인 워크플로우
        db.run(`ALTER TABLE users ADD COLUMN license_doc TEXT`, () => {});       // base64 자격증 이미지
        db.run(`ALTER TABLE users ADD COLUMN approval_status TEXT DEFAULT 'approved'`, () => {});  // approved | pending | rejected
        db.run(`ALTER TABLE users ADD COLUMN approval_note TEXT`, () => {});      // 승인/거절 사유
        db.run(`ALTER TABLE users ADD COLUMN shipping_address TEXT`, () => {});
        // 🧾 세금계산서용 사업자 정보(공급받는자 자동 반영): 회원가입~발행 연결
        db.run(`ALTER TABLE users ADD COLUMN biz_no TEXT`, () => {});         // 사업자등록번호(개인=주민 대체 가능)
        db.run(`ALTER TABLE users ADD COLUMN biz_company TEXT`, () => {});    // 상호(사업자등록증상)
        db.run(`ALTER TABLE users ADD COLUMN biz_ceo TEXT`, () => {});        // 대표자명
        db.run(`ALTER TABLE users ADD COLUMN biz_addr TEXT`, () => {});       // 사업장 주소
        db.run(`ALTER TABLE users ADD COLUMN biz_industry TEXT`, () => {});   // 업태
        db.run(`ALTER TABLE users ADD COLUMN biz_item TEXT`, () => {});       // 종목
        db.run(`ALTER TABLE users ADD COLUMN tax_email TEXT`, () => {});      // 세금계산서 수신 이메일
        db.run(`ALTER TABLE users ADD COLUMN reset_otp TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp_expiry INTEGER`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp_used INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN privacy_agreed_at TEXT`, () => {});   // 🔐 개인정보 수집·이용 동의 시각
        db.run(`ALTER TABLE users ADD COLUMN force_pwd_change INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE transfers ADD COLUMN rawDate TEXT`, () => {});
        db.run(`ALTER TABLE transfers ADD COLUMN memo TEXT`, () => {});   // 💰 정산 입금 상세(정산에 포함된 판매 항목 JSON)
        db.run(`ALTER TABLE deposits ADD COLUMN rawDate TEXT`, () => {});
        db.run(`ALTER TABLE withdrawals ADD COLUMN rawDate TEXT`, () => {});
        // 🚀 products: 패키지 메타 (대표 파일 + PDF + 추가 파일 묶음 JSON)
        db.run(`ALTER TABLE products ADD COLUMN package_data TEXT`, () => {});
        db.run(`ALTER TABLE products ADD COLUMN is_package INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE products ADD COLUMN link_url TEXT`, () => {});   // 🔗 링크 상품(외부 홈페이지 연결) — Admin 전용
        // 💳 [PG 카드결제] 결제수단·PG 승인번호 기록. balance=잔액결제, card=외부 카드(구매자 지갑 미차감). 실 PG 연동 대비.
        db.run(`ALTER TABLE transactions ADD COLUMN pay_method TEXT`, () => {});
        db.run(`ALTER TABLE transactions ADD COLUMN pg_approval TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN pay_method TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN pg_approval TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN remake_of INTEGER`, () => {});   // 🔁 리메이크/리페어: 원주문 id
        db.run(`ALTER TABLE transactions ADD COLUMN make_kind TEXT`, () => {});         // 🦷 기공: 신규제작/리메이크/리페어 구분
        db.run(`ALTER TABLE chat_rooms ADD COLUMN expire_at INTEGER`, () => {});        // ⏱ 거절 후 자동 삭제 예정 시각(epoch ms)
        db.run(`ALTER TABLE chat_rooms ADD COLUMN expire_after_id INTEGER`, () => {});  // 이 chat id 이후 새 대화 없으면 삭제
        db.run(`CREATE TABLE IF NOT EXISTS chat_hidden (user TEXT, roomId TEXT, hidden_at TEXT)`, () => {});   // 🗑 사용자가 삭제(퇴장)한 대화방(본인 목록에서 숨김)
        // 📁 2A: 다중기기 공유폴더 — 한 계정의 여러 기기와 각 기기의 공유폴더 지정 상태를 추적
        db.run(`CREATE TABLE IF NOT EXISTS devices (deviceId TEXT PRIMARY KEY, userName TEXT, name TEXT, platform TEXT, hasFolder INTEGER DEFAULT 0, folderName TEXT, lastSeen INTEGER, created INTEGER)`, () => {});
        // 📁 2B(기반): 기기별 공유폴더 파일 인덱스 — 반투명 썸네일(합집합 표시)용. 해시로 중복 제거.
        db.run(`CREATE TABLE IF NOT EXISTS device_files (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, deviceId TEXT, fname TEXT, size INTEGER, hash TEXT, thumb TEXT, mime TEXT, updated INTEGER, UNIQUE(deviceId, hash))`, () => {});
        db.run(`ALTER TABLE chats ADD COLUMN created_at TEXT`, () => {});   // ⏱ ISO 타임스탬프(고객센터 24h 자동삭제 기준)
        db.run(`ALTER TABLE users ADD COLUMN card_pw TEXT`, () => {});   // (선택) 회원가입 시 카드 비밀번호 4자리 — 실 PG 대비 저장만, 현재 미검증

        // 🚀 [v8+] 전역 설정 (Admin 권한 비밀번호 등) — 초기값 'mars'
        db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`, () => {
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_password', 'mars')`, () => {});
            // 🔐 관리자 계정 허용목록(쉼표구분 로그인ID) — 예전 공유 비밀번호 'mars' 백도어를 대체하는 신원 기반 권한. 기본: 소유자 계정.
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_users', 'hi840508')`, () => {});
            // 💳 [PG] 카드결제 모드 — 기본 mock(4자리 비번이면 승인). 실 PG 계약 후 'live'로 전환하면 _pgAuthorize의 live 분기만 구현하면 됨.
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('pg_mode', 'mock')`, () => {});
        });

        // 🧾 전자세금계산서 이력 + 정산 기본 변수(모두 settings로 변경 가능): VAT율 10%, 결제수수료율 2.7%, SW 월사용료 10000원
        db.run(`CREATE TABLE IF NOT EXISTS tax_invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transactionId INTEGER,
            seller TEXT, buyer TEXT, invoiceNo TEXT,
            issueStatus TEXT DEFAULT 'draft', ntsStatus TEXT DEFAULT 'not_sent',
            supplierBizNo TEXT, supplierName TEXT, recipientBizNo TEXT, recipientName TEXT,
            supplyAmount INTEGER DEFAULT 0, taxAmount INTEGER DEFAULT 0, totalAmount INTEGER DEFAULT 0,
            invoiceType TEXT DEFAULT 'commission', batchMonth TEXT,
            payload TEXT, paxbillResponse TEXT, created_at TEXT, updated_at TEXT
        )`, () => {
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_vat_rate', '10')`, () => {});
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_pay_fee_rate', '2.7')`, () => {});
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_sw_fee', '10000')`, () => {});
            // 💰 [정산 신규변수] 카드결제 수수료율 2.4% + 거래 수수료율 0.6% (SW월사용료·VAT 폐지). 결제수수료=두 율의 합, 지급액=매출−결제수수료.
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_card_fee_rate', '2.4')`, () => {});
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_txn_fee_rate', '0.6')`, () => {});
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_supplier', '')`, () => {});   // 공급자(플랫폼) 정보 JSON — 마지막 입력값 자동 저장
        });
        // 🔐 로그인 세션(토큰) — 자금/민감 엔드포인트의 신원을 요청 본문이 아닌 서버 세션으로 판정
        db.run(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, name TEXT, created INTEGER)`, () => {
            db.all(`SELECT token, name, created FROM sessions`, [], (e, rows) => { (rows || []).forEach(r => SESSIONS.set(r.token, { name: r.name, created: r.created })); });
        });
        // 🔔 웹 푸시 구독 저장(카톡식 알림) — endpoint 당 1행, 사용자별 다기기 허용
        db.run(`CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, userName TEXT, sub TEXT, created TEXT)`);
    });
}
initTables();
setTimeout(loadAdminUsers, 500);   // 부팅 후 admin_users 설정 반영(기본 '이재준')

// 💬 주문 대화방(room_ord_<orderId>)은 id로 참가자를 파싱할 수 없으므로 chat_rooms에서 buyer/seller를 캐시(소켓 스코프 전송용).
const ORDER_ROOMS = new Map();
function _setOrderRoom(roomId, buyer, seller) { if (roomId && String(roomId).startsWith('room_ord_')) ORDER_ROOMS.set(String(roomId), { buyer, seller }); }
function _loadOrderRooms() { db.all(`SELECT roomId, buyer, seller FROM chat_rooms WHERE roomId LIKE 'room_ord_%'`, [], (e, rows) => { (rows || []).forEach(r => { if (r.roomId) ORDER_ROOMS.set(r.roomId, { buyer: r.buyer, seller: r.seller }); }); }); }
setTimeout(_loadOrderRooms, 600);

// 🦷 [기공소 백필] 기능 추가 전 생성된 기공소 상점에도 '의뢰서 작성' 기본 상품 + 수가 시드 보장(부팅 1회, 멱등).
function _backfillLabStores() {
    db.all(`SELECT id, owner, rx_items FROM stores WHERE category = 'dental_lab'`, [], (e, stores) => {
        if (e || !stores) return;
        stores.forEach(s => {
            if (!s.rx_items) { try { db.run(`UPDATE stores SET rx_items = ? WHERE id = ?`, [JSON.stringify(_defaultRxItems()), s.id], () => {}); } catch (_) {} }
            db.get(`SELECT id FROM products WHERE storeId = ? AND rx_form = 1 LIMIT 1`, [s.id], (e2, prod) => {
                if (prod) return;   // 이미 있음 → 중복 생성 방지
                db.run(`INSERT INTO products (id, storeId, type, name, description, price_stream, price_original, seller, rx_form) VALUES (?, ?, 'html_enc', ?, ?, 0, 0, ?, 1)`,
                    ['PRD_RX_' + s.id, s.id, '의뢰서 작성 (간편/상세)', '치과 기공 의뢰서를 작성하여 주문합니다. 상세 의뢰서는 취급 품목 수가로 금액이 자동 산정됩니다.', s.owner || ''], () => {});
            });
        });
        console.log('[기공소 백필] dental_lab 상점 ' + stores.length + '곳 의뢰서 상품·수가 점검');
    });
}
setTimeout(_backfillLabStores, 1500);

// 🔐 세션 토큰: 로그인 시 발급, 이후 x-auth-token 헤더로 서버가 사용자 판정(본문 신원 위조 차단)
const SESSIONS = new Map();   // token -> { name }
function issueToken(name) {
    const token = crypto.randomBytes(24).toString('hex');
    const created = Date.now();
    SESSIONS.set(token, { name, created });
    db.run(`INSERT INTO sessions (token, name, created) VALUES (?, ?, ?)`, [token, name, created], () => {});
    return token;
}
function revokeToken(token) { if (token) { SESSIONS.delete(String(token)); db.run(`DELETE FROM sessions WHERE token = ?`, [String(token)], () => {}); } }
// 🔐 세션 유효기간 30일(길게 — 전원 로그아웃 방지). TTL 초과 세션은 무효화(created 없는 레거시 세션은 통과).
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
function authUser(req) {
    const t = req.headers['x-auth-token'] || (req.body && req.body._token) || (req.query && req.query._token);
    if (!t) return null;
    const s = SESSIONS.get(String(t));
    if (!s) return null;
    if (s.created && (Date.now() - Number(s.created)) > SESSION_TTL_MS) { revokeToken(String(t)); return null; }
    return s.name;
}
// 자금/민감 엔드포인트 가드: 로그인 필수 + acting user 반환. bodyNameField가 있으면 본문 신원과 토큰 신원 불일치 시 거부.
function requireUser(req, res) {
    const me = authUser(req);
    if (!me) { res.status(401).json({ error: '로그인이 필요합니다. (세션 만료 시 다시 로그인)' }); return null; }
    return me;
}
// 🔐 GET 소유자 스코프 가드: 로그인 필수 + path 주체(subject)가 본인이거나 관리자만. 아니면 403.
function requireSelfOrAdmin(req, res, subject) {
    const me = requireUser(req, res); if (!me) return null;
    if (me !== subject && !isAdminName(me)) { res.status(403).json({ error: '본인 정보만 조회할 수 있습니다.' }); return null; }
    return me;
}
// 📅 정산 귀속월(KST 기준 YYYY-MM). UTC toISOString은 00~09시 KST에 전월로 잘못 귀속되므로 +9h 보정.
function _kstMonth() { return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 7); }

// 🔐 간단 인메모리 레이트리미터(의존성 없음). key = route|ip|account. 실패 누적이 limit 이상이면 429(백오프 안내). 성공 시 리셋.
const RATE_BUCKETS = new Map();   // key -> { count, first }
const RATE_WINDOW_MS = 10 * 60 * 1000;   // 10분 윈도우
function _clientIp(req) {
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
    return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}
function _rateKey(req, route) { return route + '|' + _clientIp(req) + '|' + String((req.body && req.body.name) || ''); }
// 차단 검사: 초과 시 429 응답 후 true. 통과면 false.
function rateLimitHit(req, res, route, limit) {
    const key = _rateKey(req, route); const now = Date.now();
    let b = RATE_BUCKETS.get(key);
    if (b && (now - b.first) > RATE_WINDOW_MS) { RATE_BUCKETS.delete(key); b = null; }
    if (b && b.count >= limit) {
        const waitMin = Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - b.first)) / 60000));
        res.status(429).json({ error: `보안을 위해 시도가 일시 차단되었습니다. 약 ${waitMin}분 후 다시 시도해 주세요.` });
        return true;
    }
    return false;
}
function rateLimitFail(req, route) {
    const key = _rateKey(req, route); const now = Date.now();
    let b = RATE_BUCKETS.get(key);
    if (!b || (now - b.first) > RATE_WINDOW_MS) b = { count: 0, first: now };
    b.count++; RATE_BUCKETS.set(key, b);
}
function rateLimitReset(req, route) { RATE_BUCKETS.delete(_rateKey(req, route)); }

// 🔐 관리자 신원(세션 토큰 기반). ⛔ 예전 'mars' 공유 비밀번호 백도어 폐지 — settings.admin_users(쉼표구분, 기본 '이재준')에 속한 로그인 사용자만 관리자.
let ADMIN_USERS = new Set(['hi840508']);
function loadAdminUsers() {
    db.get(`SELECT value FROM settings WHERE key='admin_users'`, [], (e, row) => {
        if (row && row.value) ADMIN_USERS = new Set(String(row.value).split(',').map(s => s.trim()).filter(Boolean));
    });
}
function isAdminName(name) { return !!name && ADMIN_USERS.has(name); }

// 💳 ============================================================================================
// [PG 카드결제 심(seam)] — 실 PG(아임포트/토스/나이스페이 등) 연동 시 이 함수 + settings.pg_mode 만 손대면 됨.
//  개념: '카드 결제'는 외부 카드에서 자금이 나오므로 구매자 지갑은 차감하지 않고, 수취인(판매자/Admin)에게만 입금(PG 승인 성공 시).
//  현재 mock: 카드 비밀번호 4자리(아무 4자리)면 승인 성공. (팍스빌 mock 패턴과 동일한 어댑터 구조)
let PG_MODE = 'mock';
function loadPgMode() {
    db.get(`SELECT value FROM settings WHERE key='pg_mode'`, [], (e, row) => {
        if (row && row.value) PG_MODE = String(row.value).trim() || 'mock';
    });
}
setTimeout(loadPgMode, 500);
// 결제 승인 판정(동기). 성공 시 { ok:true, approvalNo, method:'card' }. 실패 시 { ok:false, error }.
function _pgAuthorize({ payer, amount, method, cardPw }) {
    if (method !== 'card') return { ok: false, error: '카드 결제가 아닙니다.' };
    if (PG_MODE !== 'live') {
        // ── mock: 실제 카드사 대조 없이 4자리 숫자면 승인 ──
        if (!/^\d{4}$/.test(String(cardPw == null ? '' : cardPw))) return { ok: false, error: '카드 비밀번호(4자리)를 확인하세요.' };
        return { ok: true, mock: true, approvalNo: 'PGMOCK-' + Date.now(), method: 'card' };
    }
    // ── live: 실 PG사 승인 API 호출 위치(계약 후 구현) ──
    // TODO(live): 실제 PG 결제창 승인/캡처 API 호출 후 결과 매핑. 예)
    //   const r = await fetch(process.env.PG_API_BASE + '/payments/authorize', { method:'POST',
    //       headers:{ Authorization:`Bearer ${process.env.PG_API_KEY}` },
    //       body: JSON.stringify({ amount, payer, ... }) });
    //   const d = await r.json(); return r.ok ? { ok:true, approvalNo:d.tid, method:'card', raw:d } : { ok:false, error:d.message };
    return { ok: false, error: '실 PG(pg_mode=live) 연동이 아직 설정되지 않았습니다.' };
}
// 💰 [에스크로] 자금이 귀속되는 Admin 계정(첫 관리자, 기본 hi840508). 구매 대금 보관·정산 지급의 주체.
function _adminAccount() { const a = ADMIN_USERS.values().next().value; return a || 'hi840508'; }
function requireAdmin(req, res) {
    const me = authUser(req);
    if (!me) { res.status(401).json({ error: '로그인이 필요합니다.' }); return null; }
    if (!isAdminName(me)) { res.status(403).json({ error: '관리자 권한이 필요합니다.' }); return null; }
    return me;
}

// 🔐 비밀번호 해시 — 내장 crypto.scrypt(외부 의존성 없음). 형식: "scrypt$<salt>$<hash>".
//   레거시 평문 비밀번호도 verifyPassword가 허용(로그인 성공 시 해시로 자동 업그레이드) → 기존 회원 잠김 없음.
function hashPassword(pw) {
    const salt = crypto.randomBytes(16).toString('hex');
    const h = crypto.scryptSync(String(pw == null ? '' : pw), salt, 32).toString('hex');
    return 'scrypt$' + salt + '$' + h;
}
function isHashed(stored) { return typeof stored === 'string' && stored.startsWith('scrypt$'); }
function verifyPassword(pw, stored) {
    if (stored == null) return false;
    const s = String(stored);
    if (s.startsWith('scrypt$')) {
        const parts = s.split('$'); if (parts.length !== 3) return false;
        let calc; try { calc = crypto.scryptSync(String(pw == null ? '' : pw), parts[1], 32).toString('hex'); } catch (_) { return false; }
        const a = Buffer.from(parts[2], 'hex'), b = Buffer.from(calc, 'hex');
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    return s === String(pw == null ? '' : pw);   // 레거시 평문
}
// 로그인 성공 시 레거시 평문을 해시로 승격
function upgradePasswordIfLegacy(name, stored, plain) {
    if (!isHashed(stored)) { try { db.run(`UPDATE users SET password = ? WHERE name = ?`, [hashPassword(plain), name], () => {}); } catch (_) {} }
}
// 반환 사용자 객체에서 비밀번호 필드 제거(클라이언트로 유출 금지)
function stripPwd(u) { if (u && typeof u === 'object') { const c = Object.assign({}, u); delete c.password; return c; } return u; }

// 🚀 [v8+] Admin 비밀번호 헬퍼 — DB의 settings.admin_password 사용 (초기값 'mars')
function getAdminPassword(cb) {
    db.get(`SELECT value FROM settings WHERE key = 'admin_password'`, [], (err, row) => {
        cb((row && row.value) || 'mars');
    });
}
// adminSecret 검증 미들웨어 대용 — 'mars'(레거시) 또는 현재 설정된 비밀번호 모두 허용
function verifyAdminSecret(secret, cb) {
    getAdminPassword((pw) => cb(secret === pw));   // ⛔ 'mars' 레거시 백도어 제거(이 함수 자체도 현재 미사용 — 신원 기반 requireAdmin으로 대체)
}

// ===================== 💾 [항목1] DB 자동 백업 → R2(backup/) =====================
// earth_database_master.sqlite를 매일 1회(+부팅 2분 후) R2에 gzip 백업. R2 저장·egress 무료 → 비용 0.
// VACUUM INTO로 일관성 있는 스냅샷 생성(라이브 DB 안전) → gzip → PutObject. 30일 초과 백업 자동 삭제.
let _lastDbBackup = { at: 0, key: '', ok: false, err: '' };
function backupDatabaseToR2(cb) {
    cb = cb || function () {};
    if (!_r2) { console.warn('💾 DB백업 스킵: R2 미설정'); _lastDbBackup = { at: Date.now(), key: '', ok: false, err: 'R2 미설정' }; return cb(new Error('R2 미설정')); }
    try {
        const zlib = require('zlib');
        const { PutObjectCommand } = require('@aws-sdk/client-s3');
        const d = new Date();
        const pad = n => String(n).padStart(2, '0');
        const ts = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
        const tmp = path.join(__dirname, `._dbbak_${ts}.sqlite`);
        try { fs.rmSync(tmp, { force: true }); } catch (_) {}
        db.run(`VACUUM INTO ?`, [tmp], (err) => {
            if (err) { console.error('💾 DB백업 VACUUM 실패:', err.message); _lastDbBackup = { at: Date.now(), key: '', ok: false, err: err.message }; return cb(err); }
            try {
                const raw = fs.readFileSync(tmp);
                const gz = zlib.gzipSync(raw);
                const key = `backup/earth_${ts}.sqlite.gz`;
                _r2.client.send(new PutObjectCommand({ Bucket: _r2.bucket, Key: key, Body: gz, ContentType: 'application/gzip' }))
                    .then(() => {
                        _lastDbBackup = { at: Date.now(), key, ok: true, err: '' };
                        console.log(`💾 DB 백업 완료 → R2 ${key} (압축 ${(gz.length / 1048576).toFixed(2)}MB / 원본 ${(raw.length / 1048576).toFixed(2)}MB)`);
                        pruneOldDbBackups();
                        cb(null, key);
                    })
                    .catch(e => { console.error('💾 DB백업 업로드 실패:', e && e.message); _lastDbBackup = { at: Date.now(), key: '', ok: false, err: (e && e.message) || 'upload' }; cb(e); })
                    .finally(() => { try { fs.rmSync(tmp, { force: true }); } catch (_) {} });
            } catch (e) { console.error('💾 DB백업 처리 오류:', e && e.message); try { fs.rmSync(tmp, { force: true }); } catch (_) {} _lastDbBackup = { at: Date.now(), key: '', ok: false, err: (e && e.message) || 'proc' }; cb(e); }
        });
    } catch (e) { console.error('💾 DB백업 오류:', e && e.message); cb(e); }
}
const DB_BACKUP_RETAIN_MS = 30 * 24 * 60 * 60 * 1000;   // 30일 보관
function pruneOldDbBackups() {
    if (!_r2) return;
    try {
        const { ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
        const cutoff = Date.now() - DB_BACKUP_RETAIN_MS;
        const rx = /^backup\/earth_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})\.sqlite\.gz$/;
        let token, toDel = [];
        const run = () => _r2.client.send(new ListObjectsV2Command({ Bucket: _r2.bucket, Prefix: 'backup/', ContinuationToken: token }))
            .then(out => {
                (out.Contents || []).forEach(o => {
                    const m = rx.exec(o.Key || '');
                    if (m) { const t = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime(); if (t < cutoff) toDel.push({ Key: o.Key }); }
                });
                if (out.IsTruncated) { token = out.NextContinuationToken; return run(); }
                for (let i = 0; i < toDel.length; i += 1000) _r2.client.send(new DeleteObjectsCommand({ Bucket: _r2.bucket, Delete: { Objects: toDel.slice(i, i + 1000) } })).catch(() => {});
                if (toDel.length) console.log('💾 오래된 DB백업 삭제:', toDel.length, '개 (30일 초과)');
            }).catch(e => console.warn('DB백업 정리:', e && e.message));
        run();
    } catch (e) {}
}
setTimeout(() => backupDatabaseToR2(), 2 * 60 * 1000);
setInterval(() => backupDatabaseToR2(), 24 * 60 * 60 * 1000);

// 관리자 수동 백업/조회/복원용 — index.html 관리자 화면에서 호출
app.post('/api/admin/db-backup', (req, res) => {
    if (!requireAdmin(req, res)) return;
    backupDatabaseToR2((err, key) => {
        if (err) return res.status(500).json({ error: (err.message || '백업 실패') });
        res.json({ ok: true, key, at: _lastDbBackup.at });
    });
});
app.get('/api/admin/db-backups', (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (!_r2) return res.json({ last: _lastDbBackup, items: [] });
    try {
        const { ListObjectsV2Command } = require('@aws-sdk/client-s3');
        const rx = /^backup\/earth_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})\.sqlite\.gz$/;
        let token, items = [];
        const run = () => _r2.client.send(new ListObjectsV2Command({ Bucket: _r2.bucket, Prefix: 'backup/', ContinuationToken: token }))
            .then(out => {
                (out.Contents || []).forEach(o => {
                    const m = rx.exec(o.Key || '');
                    if (m) items.push({ key: o.Key, size: o.Size, at: new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime() });
                });
                if (out.IsTruncated) { token = out.NextContinuationToken; return run(); }
                items.sort((a, b) => b.at - a.at);
                res.json({ last: _lastDbBackup, items });
            }).catch(e => res.status(500).json({ error: (e && e.message) || 'list 실패' }));
        run();
    } catch (e) { res.status(500).json({ error: (e && e.message) || 'list 오류' }); }
});
app.get('/api/admin/db-backup/download', (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const key = String(req.query.key || '');
    if (!/^backup\/earth_\d{8}_\d{6}\.sqlite\.gz$/.test(key)) return res.status(400).json({ error: '잘못된 키' });
    try {
        const { GetObjectCommand } = require('@aws-sdk/client-s3');
        const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
        getSignedUrl(_r2.client, new GetObjectCommand({ Bucket: _r2.bucket, Key: key }), { expiresIn: 600 })
            .then(url => res.json({ url })).catch(e => res.status(500).json({ error: (e && e.message) || 'presign 실패' }));
    } catch (e) { res.status(500).json({ error: (e && e.message) || 'download 오류' }); }
});
app.get('/api/admin/r2-usage', (req, res) => {
    if (!requireAdmin(req, res)) return;
    _r2Usage((err, u) => { if (err) return res.status(500).json({ error: err.message || 'usage 실패' }); res.json(u); });
});
// 📊 회원별 클라우드 사용현황(미러 백업 사용량 + 구매/사용 용량) — 관리자 모니터링
app.get('/api/admin/cloud-usage', (req, res) => {
    if (!requireAdmin(req, res)) return;
    db.all(`SELECT userName AS name, COALESCE(SUM(size),0) AS mirrorBytes, COUNT(*) AS files FROM mirror_files GROUP BY userName`, [], (e, mrows) => {
        if (e) return res.status(500).json({ error: e.message });
        db.all(`SELECT name, purchasedBytes, usedBytes FROM cloud_storage`, [], (e2, crows) => {
            const map = {};
            const ensure = (n) => (map[n] = map[n] || { name: n, mirrorBytes: 0, files: 0, purchasedBytes: 0, usedBytes: 0 });
            (crows || []).forEach(c => { const m = ensure(c.name); m.purchasedBytes = c.purchasedBytes || 0; m.usedBytes = c.usedBytes || 0; });
            (mrows || []).forEach(r => { const m = ensure(r.name); m.mirrorBytes = r.mirrorBytes || 0; m.files = r.files || 0; });
            const users = Object.values(map).sort((a, b) => (b.mirrorBytes + b.usedBytes) - (a.mirrorBytes + a.usedBytes));
            res.json({
                free: CLOUD_FREE_BYTES, pricePerGB: CLOUD_PRICE_PER_GB, users,
                totalMirror: users.reduce((s, u) => s + u.mirrorBytes, 0),
                totalPurchased: users.reduce((s, u) => s + u.purchasedBytes, 0),
                totalUsed: users.reduce((s, u) => s + u.usedBytes, 0)
            });
        });
    });
});
// 🧹 특정 회원의 미러 백업 강제 정리 → mirror_files 삭제 + R2 오브젝트 삭제(용량 회수)
app.post('/api/admin/mirror-purge', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const userName = String(req.body.userName || '');
    if (!userName) return res.status(400).json({ error: 'userName 필요' });
    db.all(`SELECT key, size FROM mirror_files WHERE userName = ?`, [userName], (e, rows) => {
        if (e) return res.status(500).json({ error: e.message });
        const keys = (rows || []).map(r => r.key).filter(Boolean);
        const freed = (rows || []).reduce((s, r) => s + (r.size || 0), 0);
        db.run(`DELETE FROM mirror_files WHERE userName = ?`, [userName], (de) => {
            if (de) return res.status(500).json({ error: de.message });
            if (_r2 && keys.length) {
                try {
                    const { DeleteObjectsCommand } = require('@aws-sdk/client-s3');
                    for (let i = 0; i < keys.length; i += 1000) {
                        _r2.client.send(new DeleteObjectsCommand({ Bucket: _r2.bucket, Delete: { Objects: keys.slice(i, i + 1000).map(k => ({ Key: k })) } })).catch(() => {});
                    }
                } catch (_) {}
            }
            res.json({ ok: true, count: keys.length, freed });
        });
    });
});

// Admin 권한 비밀번호 확인 (활성화용)
app.post('/api/admin/verify-password', (req, res) => {
    if (rateLimitHit(req, res, 'admin-pw', 5)) return;   // 🔐 Admin 비번 오라클 무차별 방지(5회)
    getAdminPassword((pw) => {
        const ok = (req.body.password || '') === pw;
        if (ok) rateLimitReset(req, 'admin-pw'); else rateLimitFail(req, 'admin-pw');
        res.json({ ok });
    });
});
// Admin 권한 비밀번호 변경 (현재 비밀번호 확인 후)
app.post('/api/admin/change-password', (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if(!newPassword || String(newPassword).length < 2) return res.status(400).json({ error: '새 비밀번호가 너무 짧습니다.' });
    getAdminPassword((pw) => {
        if((currentPassword || '') !== pw) return res.status(403).json({ error: '현재 Admin 비밀번호가 일치하지 않습니다.' });
        db.run(`UPDATE settings SET value = ? WHERE key = 'admin_password'`, [String(newPassword)], () => {
            res.json({ success: true });
        });
    });
});

app.post('/api/admin/db-reset', (req, res) => {
    if(!requireAdmin(req,res)) return;
    db.serialize(() => {
        const tables = ['users', 'friends', 'stores', 'products', 'transactions', 'chats', 'qr_checks', 'transfers', 'deposits', 'withdrawals', 'favorite_stores', 'refund_requests', 'product_orders', 'chat_rooms', 'product_reviews'];
        tables.forEach(t => db.run(`DROP TABLE IF EXISTS ${t}`));
        initTables(); res.json({ success: true });
    });
});

// 🔒 통합 뷰어 DRM: 생성 시 복호 키 위탁(서버 보관)
app.post('/api/viewer/register', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // \ud83d\udd10 \ub85c\uadf8\uc778 \ud544\uc218
    const { fileId, k, expiry, title } = req.body || {};
    if (!fileId || !k) return res.status(400).json({ error: 'fileId/k \ud544\uc694' });
    db.get(`SELECT boundUser, firstOpenedAt, creator FROM viewer_files WHERE fileId = ?`, [fileId], (e, prev) => {
        if (e) return res.status(500).json({ error: e.message });
        // \ud83d\udd10 \uc2e0\uaddc(creator null)\ub9cc \uc0c8\ub85c \ub4f1\ub85d, \uae30\uc874 \ud30c\uc77c\uc740 \uc6d0 \ub4f1\ub85d\uc790(creator)\ub9cc \ub36e\uc5b4\uc4f0\uae30 \uac00\ub2a5(\ud0c0\uc778 \ud0a4 \uad50\uccb4 \ucc28\ub2e8). creator\ub294 \uc138\uc158 \uc2e0\uc6d0\uc73c\ub85c \uac15\uc81c(\ubcf8\ubb38 creator \ubb34\uc2dc).
        if (prev && prev.creator && prev.creator !== me) return res.status(403).json({ error: '\uc774 \ubdf0\uc5b4 \ud30c\uc77c\uc758 \ub4f1\ub85d\uc790\ub9cc \uac31\uc2e0\ud560 \uc218 \uc788\uc2b5\ub2c8\ub2e4.' });
        db.run(`INSERT OR REPLACE INTO viewer_files (fileId,k,expiry,creator,title,boundUser,firstOpenedAt,createdAt) VALUES (?,?,?,?,?,?,?,?)`,
            [fileId, String(k), Number(expiry) || 0, (prev && prev.creator) || me, title || '', (prev && prev.boundUser) || null, (prev && prev.firstOpenedAt) || null, Date.now()],
            (err) => { if (err) return res.status(500).json({ error: err.message }); res.json({ ok: true }); });
    });
});
// 🔒 통합 뷰어 DRM: 열람 시 잠금해제 — 로그인 검증 + 만료 + 최초개봉 ID 바인딩 → 키 전달
app.post('/api/viewer/unlock', (req, res) => {
    const { fileId, userName, password } = req.body || {};
    if (!fileId || !userName) return res.status(400).json({ error: '\uc815\ubcf4 \ubd80\uc871' });
    const rec = (ok, reason) => db.run(`INSERT INTO viewer_opens (fileId,userName,at,ok,reason) VALUES (?,?,?,?,?)`, [fileId, userName, Date.now(), ok ? 1 : 0, reason || ''], () => {});
    db.get(`SELECT * FROM users WHERE name = ?`, [userName], (e, u) => {
        if (e) return res.status(500).json({ error: e.message });
        if (!u || !verifyPassword(password, u.password)) { rec(0, 'auth'); return res.status(401).json({ error: 'ID \ub610\ub294 \ube44\ubc00\ubc88\ud638\uac00 \uc62c\ubc14\ub974\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4.' }); }
        upgradePasswordIfLegacy(u.name, u.password, password);
        db.get(`SELECT * FROM viewer_files WHERE fileId = ?`, [fileId], (e2, f) => {
            if (e2) return res.status(500).json({ error: e2.message });
            if (!f) { rec(0, 'noreg'); return res.status(404).json({ error: '\ub4f1\ub85d\ub418\uc9c0 \uc54a\uc740 \ubdf0\uc5b4 \ud30c\uc77c\uc785\ub2c8\ub2e4.' }); }
            const now = Date.now();
            if (f.expiry && now > f.expiry) { rec(0, 'expired'); return res.status(403).json({ error: '\uc5f4\ub78c \uae30\uac04\uc774 \ub9cc\ub8cc\ub418\uc5c8\uc2b5\ub2c8\ub2e4.', expired: true }); }
            if (f.boundUser && f.boundUser !== userName) { rec(0, 'bound'); return res.status(403).json({ error: '\uc774 \ud30c\uc77c\uc740 \ub2e4\ub978 \uacc4\uc815(' + f.boundUser + ')\uc5d0 \uc5f0\uacb0\ub418\uc5b4 \ub2e4\ub978 ID\ub85c\ub294 \uc5f4 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4.', bound: true }); }
            if (!f.boundUser) db.run(`UPDATE viewer_files SET boundUser=?, firstOpenedAt=? WHERE fileId=?`, [userName, now, fileId], () => {});
            rec(1, f.boundUser ? 'open' : 'firstbind');
            res.json({ ok: true, k: f.k, boundUser: f.boundUser || userName, firstOpen: !f.boundUser });
        });
    });
});

app.post('/api/auth/verify', (req, res) => {
    if (rateLimitHit(req, res, 'login', 8)) return;   // 🔐 로그인 무차별 대입 방지(8회)
    db.get(`SELECT * FROM users WHERE name = ?`, [req.body.name], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            if (verifyPassword(req.body.password, row.password)) {
                rateLimitReset(req, 'login');
                upgradePasswordIfLegacy(row.name, row.password, req.body.password);
                res.json({ exists: true, user: Object.assign(stripPwd(row), { isAdmin: isAdminName(row.name) }), token: issueToken(row.name), mustChangePassword: !!row.force_pwd_change, isAdmin: isAdminName(row.name) });
            }
            else { rateLimitFail(req, 'login'); res.status(401).json({ exists: true, error: "비밀번호가 불일치합니다." }); }
        } else { rateLimitFail(req, 'login'); res.json({ exists: false }); }
    });
});

// 🚀 [v8+] ID 중복 검사
app.post('/api/auth/check-id', (req, res) => {
    const name = (req.body.name || '').trim();
    if(!name) return res.json({ available: false, reason: 'ID를 입력해 주세요.' });
    if(name.length < 3) return res.json({ available: false, reason: 'ID는 3자 이상이어야 합니다.' });
    if(!/^[a-zA-Z0-9_가-힣]{3,}$/.test(name)) return res.json({ available: false, reason: '영문/숫자/한글/언더바만 사용 가능합니다.' });
    db.get(`SELECT name FROM users WHERE name = ?`, [name], (err, row) => {
        if(err) return res.status(500).json({ error: err.message });
        if(row) return res.json({ available: false, reason: '이미 사용 중인 ID입니다.' });
        res.json({ available: true });
    });
});

app.post('/api/auth/logout', (req, res) => { revokeToken(req.headers['x-auth-token']); res.json({ success: true }); });

app.post('/api/auth/register', (req, res) => {
    const { name, password, realname, bank, account, phone, email, shipping_address, business_type, license_doc, privacy_agreed } = req.body;
    // 🧾 세금계산서용 사업자 정보(선택 — 사업자는 발행 자동반영에 사용)
    const biz_no = _digits(req.body.biz_no || ''), biz_company = String(req.body.biz_company || ''), biz_ceo = String(req.body.biz_ceo || ''),
          biz_addr = String(req.body.biz_addr || ''), biz_industry = String(req.body.biz_industry || ''), biz_item = String(req.body.biz_item || ''),
          tax_email = String(req.body.tax_email || email || '');
    // 🔐 개인정보 수집·이용 동의(필수) — 미동의 시 가입 거부
    if(!privacy_agreed) return res.status(400).json({ error: '개인정보 수집·이용 동의가 필요합니다.' });
    // 🚀 [v8+] 의료·약무 관련 업종은 자격증 필수 + Admin 승인 대기
    const regulated = ['dental_lab', 'dental_clinic', 'medical', 'pharmacy', 'medical_wholesale'];
    const needsApproval = regulated.includes(business_type);
    if(needsApproval && !license_doc) return res.status(400).json({ error: '해당 업종은 자격증 업로드가 필수입니다.' });
    const approvalStatus = needsApproval ? 'pending' : 'approved';
    const privacyAgreedAt = new Date().toISOString();   // 동의 시각 기록(보관 근거)

    // 💳 (선택) 카드 비밀번호 4자리 — 실 PG 대비 저장만(현재 미검증). 형식 안 맞으면 저장 안 함.
    const cardPwRaw = _digits(req.body.card_pw || ''); const cardPw = /^\d{4}$/.test(cardPwRaw) ? cardPwRaw : null;
    // ⛔ 가입 축하금(10,000원) 정책 폐지 — 모든 신규 계정은 잔액 0으로 시작.
    db.run(`INSERT INTO users (name, password, realname, bank, account, balance, phone, email, shipping_address, business_type, license_doc, approval_status, privacy_agreed_at, biz_no, biz_company, biz_ceo, biz_addr, biz_industry, biz_item, tax_email, card_pw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, hashPassword(password), realname, bank, account, 0, phone || '', email || '', shipping_address || '', business_type || 'individual', license_doc || null, approvalStatus, privacyAgreedAt, biz_no, biz_company, biz_ceo, biz_addr, biz_industry, biz_item, tax_email, cardPw], (err) => {
        if (err) return res.status(500).json({ error: "회원 ID 중복 또는 생성 에러" });
        res.json({
            name, realname, bank, account,
            phone: phone || '', email: email || '', shipping_address: shipping_address || '',
            business_type: business_type || 'individual',
            approval_status: approvalStatus,
            balance: 0,
            profilePic: null,
            needsApproval,
            token: needsApproval ? null : issueToken(name),
            isAdmin: isAdminName(name)
        });
    });
});

// 🚀 [v8+] Admin: 가입 승인 대기 회원 목록
app.get('/api/admin/pending-users', (req, res) => {
    if(!requireAdmin(req,res)) return;
    db.all(`SELECT name, realname, business_type, phone, email, license_doc, approval_status, approval_note FROM users WHERE approval_status = 'pending' ORDER BY name`, [], (err, rows) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 🚀 [v8+] Admin: 승인 / 반려
app.post('/api/admin/approve-user', (req, res) => {
    const { name, decision, note } = req.body;
    if(!requireAdmin(req,res)) return;
    if(!['approved', 'rejected'].includes(decision)) return res.status(400).json({ error: '잘못된 결정값' });
    db.run(`UPDATE users SET approval_status = ?, approval_note = ? WHERE name = ?`, [decision, note || '', name], function(err) {
        if(err) return res.status(500).json({ error: err.message });
        if(this.changes === 0) return res.status(404).json({ error: '회원을 찾을 수 없음' });
        // ⛔ 가입 축하금(10,000원) 정책 폐지 — 승인 시에도 지급 없음. 모든 계정 잔액 0 시작.
        res.json({ success: true, decision });
    });
});

app.post('/api/user/update', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    // 🔐 본인 계정만 수정 가능(예전: 무인증 → 타인 계정 탈취 가능)
    if (req.body.name && req.body.name !== me) return res.status(403).json({ error: '본인 계정만 수정할 수 있습니다.' });
    const target = me;
    // 비밀번호는 새로 입력했을 때만 변경(빈 값이면 유지) + 해시 저장
    const pw = req.body.password;
    // 🧾 세금계산서용 사업자 정보 — 값이 오면 갱신, 없으면(undefined) 기존 유지(COALESCE)
    const bz = req.body, hasBz = (k) => (bz[k] !== undefined ? (k==='biz_no' ? _digits(bz[k]) : String(bz[k])) : null);
    const bizSet = `, biz_no = COALESCE(?, biz_no), biz_company = COALESCE(?, biz_company), biz_ceo = COALESCE(?, biz_ceo), biz_addr = COALESCE(?, biz_addr), biz_industry = COALESCE(?, biz_industry), biz_item = COALESCE(?, biz_item), tax_email = COALESCE(?, tax_email)`;
    const bizVals = [hasBz('biz_no'), hasBz('biz_company'), hasBz('biz_ceo'), hasBz('biz_addr'), hasBz('biz_industry'), hasBz('biz_item'), hasBz('tax_email')];
    if (pw && String(pw).length > 0) {
        db.run(`UPDATE users SET password = ?, realname = ?, bank = ?, account = ?, profilePic = ?, phone = ?, email = ?, shipping_address = ?${bizSet} WHERE name = ?`,
            [hashPassword(pw), req.body.realname, req.body.bank, req.body.account, req.body.profilePic, req.body.phone || '', req.body.email || '', req.body.shipping_address || '', ...bizVals, target],
            () => res.json({ success: true }));
    } else {
        db.run(`UPDATE users SET realname = ?, bank = ?, account = ?, profilePic = ?, phone = ?, email = ?, shipping_address = ?${bizSet} WHERE name = ?`,
            [req.body.realname, req.body.bank, req.body.account, req.body.profilePic, req.body.phone || '', req.body.email || '', req.body.shipping_address || '', ...bizVals, target],
            () => res.json({ success: true }));
    }
});

// 🚀 비밀번호 변경 후 force_pwd_change 플래그 해제
app.post('/api/user/change-password', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const { name, newPassword } = req.body;
    if (name && name !== me) return res.status(403).json({ error: '본인 계정만 변경할 수 있습니다.' });
    if(!newPassword || newPassword.length < 4) return res.status(400).json({ error: "비밀번호는 4자 이상이어야 합니다." });
    db.run(`UPDATE users SET password = ?, force_pwd_change = 0, reset_otp = NULL, reset_otp_expiry = NULL, reset_otp_used = 0 WHERE name = ?`,
        [hashPassword(newPassword), me], (err) => {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
});

// 🚀 회원 검색 (이름/실명/전화로 부분 매칭) - 친구 등록용
app.get('/api/users/search', (req, res) => {
    const q = (req.query.q || '').trim(); const exclude = req.query.exclude || '';
    if(!q || q.length < 1) return res.json([]);
    const like = `%${q}%`;
    db.all(`SELECT name, profilePic, phone, realname FROM users WHERE (name LIKE ? OR realname LIKE ? OR phone LIKE ?) AND name != ? LIMIT 20`,
        [like, like, like, exclude], (err, rows) => res.json(rows || []));
});
// 🚀 전체 사용자 정보 (잔액 + 프로필 + 전화 + 이메일 + 주소)
//  🔐 준(semi)공개: 이름/프로필/실명은 누구나(공개 표시용), PII(전화/이메일/주소/사업자/세금이메일)는 본인·관리자만.
app.get('/api/users/:name', (req, res) => {
    const caller = authUser(req);   // 무인증 허용(공개 표시용) — 필드 게이팅으로 PII 보호
    const target = req.params.name;
    db.get(`SELECT name, balance, profilePic, phone, email, shipping_address, realname, business_type, biz_no, biz_company, biz_ceo, biz_addr, biz_industry, biz_item, tax_email FROM users WHERE name = ?`, [target], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.json({ balance: 0 });
        const isOwner = !!caller && (caller === target || isAdminName(caller));
        if (!isOwner) {
            ['phone', 'email', 'shipping_address', 'biz_no', 'biz_company', 'biz_ceo', 'biz_addr', 'biz_industry', 'biz_item', 'tax_email'].forEach(k => { delete row[k]; });
        }
        res.json(row);
    });
});

// 🚀 ============ 비밀번호 찾기 (OTP 흐름) ============
// Step 1: ID로 가입된 이메일 조회 (마스킹된 형태 반환)
app.post('/api/auth/find-email', (req, res) => {
    const { name } = req.body;
    db.get(`SELECT email FROM users WHERE name = ?`, [name], (err, row) => {
        if(!row) return res.status(404).json({ error: "해당 ID로 가입된 회원이 없습니다." });
        if(!row.email) return res.status(400).json({ error: "등록된 이메일이 없습니다. 관리자(Admin)에게 비밀번호 복구를 요청해 주세요." });
        // 이메일 마스킹: a***@domain.com
        const masked = row.email.replace(/^(.{1,2})(.*)(@.*)$/, (m, p1, p2, p3) => p1 + '*'.repeat(Math.max(p2.length, 3)) + p3);
        res.json({ name, maskedEmail: masked });
    });
});

// Step 2: OTP 생성 및 (이메일 발송 시뮬레이션) - 데모 환경이므로 응답에 OTP 동봉
app.post('/api/auth/send-otp', (req, res) => {
    if (rateLimitHit(req, res, 'send-otp', 5)) return;   // 🔐 OTP 발송 남용 방지(5회)
    rateLimitFail(req, 'send-otp');   // 발송 자체를 1회로 카운트(성공/실패 무관 — 스팸 발송 제한)
    const { name } = req.body;
    db.get(`SELECT email FROM users WHERE name = ?`, [name], (err, row) => {
        if(!row || !row.email) return res.status(404).json({ error: "사용자 또는 이메일 정보가 없습니다." });
        const otp = crypto.randomInt(100000, 1000000).toString();   // 예측 어려운 난수 OTP
        const expiry = Date.now() + 10 * 60 * 1000; // 10분
        db.run(`UPDATE users SET reset_otp = ?, reset_otp_expiry = ?, reset_otp_used = 0 WHERE name = ?`,
            [otp, expiry, name], (e2) => {
                if(e2) return res.status(500).json({ error: e2.message });
                console.log(`[OTP 발송] ${name} (${row.email}) → ${otp}  (10분 유효)`);
                // 🔐 OTP를 응답에 노출하지 않음(예전 demo_otp = 계정 탈취 취약점). 서버 콘솔/이메일로만 전달.
                //   이메일 발송(SES/sendgrid 등) 미구성 시 자가복구 대신 Admin이 reset-password로 복구.
                res.json({ success: true, email: row.email, otp_sent: true, expires_in_minutes: 10 });
            });
    });
});

// Step 3: OTP로 로그인 → 1회용 토큰 검증 + force_pwd_change 플래그 ON
app.post('/api/auth/login-with-otp', (req, res) => {
    if (rateLimitHit(req, res, 'otp-login', 5)) return;   // 🔐 OTP 무차별 대입 방지(5회)
    const { name, otp } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if(!row) { rateLimitFail(req, 'otp-login'); return res.status(404).json({ error: "ID를 찾을 수 없습니다." }); }
        if(!row.reset_otp) return res.status(400).json({ error: "발급된 OTP가 없습니다. 먼저 OTP를 요청해 주세요." });
        if(row.reset_otp_used) return res.status(400).json({ error: "이미 사용된 OTP입니다." });
        if(Date.now() > Number(row.reset_otp_expiry || 0)) return res.status(400).json({ error: "OTP가 만료되었습니다. 다시 요청해 주세요." });
        if(row.reset_otp !== String(otp).trim()) { rateLimitFail(req, 'otp-login'); return res.status(401).json({ error: "OTP가 일치하지 않습니다." }); }
        rateLimitReset(req, 'otp-login');
        // OTP 사용 처리 + 비밀번호 강제 변경 플래그 설정
        db.run(`UPDATE users SET reset_otp_used = 1, force_pwd_change = 1 WHERE name = ?`, [name], (e2) => {
            row.force_pwd_change = 1;
            res.json({ success: true, user: Object.assign(stripPwd(row), { isAdmin: isAdminName(row.name) }), token: issueToken(row.name), mustChangePassword: true, isAdmin: isAdminName(row.name) });
        });
    });
});

// 🚀 Admin 전용: 모든 회원 정보 조회 (복구 목적)
app.post('/api/admin/all-users', (req, res) => {
    if(!requireAdmin(req,res)) return;
    // 🔐 비밀번호(해시)는 반환하지 않음 — 평문 덤프 취약점 제거. 복구는 admin/reset-password 사용.
    db.all(`SELECT name, realname, bank, account, phone, email, shipping_address, balance,
            CASE WHEN password LIKE 'scrypt$%' THEN '해시' ELSE '평문(미로그인)' END as pwState,
            CASE WHEN profilePic IS NOT NULL AND profilePic != '' THEN '있음' ELSE '없음' END as hasPic
            FROM users ORDER BY name`, [], (err, rows) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 🚀 Admin 전용: 특정 회원 비밀번호 강제 재설정 (복구 목적)
app.post('/api/admin/reset-password', (req, res) => {
    if(!requireAdmin(req,res)) return;
    const { targetName, newPassword } = req.body;
    if(!targetName || !newPassword) return res.status(400).json({ error: "필수 필드 누락" });
    db.run(`UPDATE users SET password = ?, force_pwd_change = 0, reset_otp = NULL, reset_otp_expiry = NULL, reset_otp_used = 0 WHERE name = ?`,
        [hashPassword(newPassword), targetName], function(err) {
            if(err) return res.status(500).json({ error: err.message });
            if(this.changes === 0) return res.status(404).json({ error: "회원을 찾을 수 없습니다." });
            res.json({ success: true });
        });
});

app.post('/api/friend/add', (req, res) => {
    const userName = requireUser(req, res); if (!userName) return;   // 🔐 신원=토큰(본문 userName 무시)
    const { friendName } = req.body;
    if(userName === friendName) return res.status(400).json({ error: "본인 ID는 추가할 수 없습니다." });
    db.get(`SELECT name, profilePic FROM users WHERE name = ?`, [friendName], (err, row) => {
        if(!row) return res.status(404).json({ error: "미존재 회원 식별자" });
        db.get(`SELECT name, profilePic FROM users WHERE name = ?`, [userName], (e2, meRow) => {
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [userName, friendName], () => {
                db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [friendName, userName], () => {
                    // 🚀 socket으로 양측에 친구 추가 사실 즉시 알림 → 별도 새로고침 없이 친구목록/대화방 갱신
                    try {
                        io.emit('friend_added', { a: userName, b: friendName, aPic: meRow && meRow.profilePic || null, bPic: row.profilePic || null });
                    } catch(e) {}
                    res.json({ success: true, partner: row });
                });
            });
        });
    });
});
app.get('/api/friends/:userName', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.userName)) return;   // 🔐 본인 친구목록만
    db.all(`SELECT u.name, u.profilePic FROM friends f JOIN users u ON f.friendName = u.name WHERE f.userName = ?`, [req.params.userName], (err, rows) => res.json(rows || []));
});

// 🧑‍🤝‍🧑 친구 삭제(양방향). 대화(chats)는 유지 → 재등록 시 이어짐.
app.post('/api/friend/remove', (req, res) => {
    const userName = requireUser(req, res); if (!userName) return;   // 🔐 신원=토큰
    const { friendName } = req.body;
    if (!friendName) return res.status(400).json({ error: '삭제 대상이 없습니다.' });
    db.run(`DELETE FROM friends WHERE (userName=? AND friendName=?) OR (userName=? AND friendName=?)`, [userName, friendName, friendName, userName], function(e) {
        if (e) return res.status(500).json({ error: e.message });
        res.json({ success: true });
    });
});

// 🔔 방별 정확한 미읽음 개수 — 클라이언트가 보유한 방별 읽음 id(reads)를 받아, 그 이후 상대/시스템 외 메시지 수를 반환
app.post('/api/chat/unread-counts', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const reads = (req.body && req.body.reads) || {};
    const roomIds = Object.keys(reads);
    if (!roomIds.length) return res.json({});
    // 🗑 내가 퇴장(숨김)한 방은 미읽음 0 (유령 배지 방지)
    db.all(`SELECT roomId FROM chat_hidden WHERE user = ?`, [me], (eh, hrows) => {
        const hidden = new Set((hrows || []).map(r => r.roomId));
        const out = {}; let pending = roomIds.length;
        roomIds.forEach(rid => {
            if (hidden.has(rid)) { out[rid] = 0; if (--pending === 0) res.json(out); return; }
            const readId = Number(reads[rid]) || 0;
            db.get(`SELECT COUNT(*) AS c FROM chats WHERE roomId = ? AND id > ? AND sender != ? AND sender != '__system__'`, [rid, readId, me], (e, row) => {
                out[rid] = (row && row.c) || 0;
                if (--pending === 0) res.json(out);
            });
        });
    });
});

app.get('/api/chat/active-rooms/:name', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.name)) return;   // 🔐 본인 활성 대화방만
    const name = req.params.name;
    // A) 일반(쌍) 대화방: chats에서 room_msg_ 마지막 메시지 + INSTR 참가자 매칭
    const qPair = `SELECT id, roomId, sender, message, date FROM chats
        WHERE id IN (SELECT MAX(id) FROM chats WHERE roomId LIKE 'room_msg_%' GROUP BY roomId)
          AND INSTR('_' || roomId || '_', '_' || ? || '_') > 0`;
    // B) 💬 주문 대화방(room_ord_): chat_rooms에서 ended=0 인 것만(구매확정 시 ended=1로 목록에서 사라짐) + 마지막 메시지
    const qOrder = `SELECT cr.roomId, cr.buyer, cr.seller, cr.storeName, cr.lastProductName,
                           c.id AS lastMsgId, c.sender AS lastSender, c.message AS lastMsg, c.date AS lastDate,
                           (SELECT status FROM product_orders WHERE ('room_ord_' || id) = cr.roomId) AS orderStatus
                    FROM chat_rooms cr
                    LEFT JOIN chats c ON c.id = (SELECT MAX(id) FROM chats WHERE roomId = cr.roomId)
                    WHERE cr.roomId LIKE 'room_ord_%' AND cr.ended = 0 AND (cr.buyer = ? OR cr.seller = ?)`;
    db.all(qPair, [name], (e1, pairRows) => {
        db.all(qOrder, [name, name], (e2, ordRows) => {
            const out = [];
            (pairRows || []).forEach(r => {
                const parts = String(r.roomId).replace('room_msg_', '').split('_');
                const partnerName = parts.filter(n => n !== name)[0] || '이재준';
                out.push({ roomId: r.roomId, partnerName, lastMsg: r.message, lastDate: r.date, lastMsgId: r.id, lastSender: r.sender, isOrder: false });
            });
            (ordRows || []).forEach(r => {
                const partnerName = (r.buyer === name) ? r.seller : r.buyer;
                out.push({ roomId: r.roomId, partnerName: partnerName || '', lastMsg: r.lastMsg || ('[' + (r.lastProductName || '주문') + '] 대화'), lastDate: r.lastDate || '', lastMsgId: r.lastMsgId || 0, lastSender: r.lastSender || '', isOrder: true, storeName: r.storeName || '', productName: r.lastProductName || '', orderStatus: r.orderStatus || '' });
            });
            const tasks = out.map(o => new Promise(resolve => {
                db.get(`SELECT profilePic FROM users WHERE name = ?`, [o.partnerName], (e, u) => { o.partnerPic = u ? u.profilePic : null; resolve(o); });
            }));
            Promise.all(tasks).then(result => {
                result.sort((a, b) => (new Date(b.lastDate || 0).getTime() || 0) - (new Date(a.lastDate || 0).getTime() || 0));
                // 🗑 내가 삭제(퇴장)한 대화방은 목록에서 제외
                db.all(`SELECT roomId FROM chat_hidden WHERE user = ?`, [name], (eh, hrows) => {
                    const hidden = new Set((hrows || []).map(r => r.roomId));
                    res.json(result.filter(r => !hidden.has(r.roomId)));
                });
            }).catch(() => res.json(out));
        });
    });
});

// 🗑 대화방 삭제(퇴장) — 주문 대화방이 아닌 일반 대화방만. 본인 목록에서 숨기고 상대에게 퇴장 안내.
app.post('/api/chat/leave-room', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const roomId = String((req.body && req.body.roomId) || '');
    if (!roomId) return res.status(400).json({ error: 'roomId가 필요합니다.' });
    if (roomId.indexOf('이재준') >= 0) return res.status(400).json({ error: '고객센터 대화방은 삭제할 수 없습니다.' });
    // 내 목록에서만 조용히 제거(종료된 주문방) / 상대에게 퇴장 안내(일반 방)
    const _doHide = (silent) => {
        db.run(`INSERT INTO chat_hidden (user, roomId, hidden_at) VALUES (?, ?, ?)`, [me, roomId, new Date().toISOString()], () => {
            // 🗑 양쪽 참가자가 모두 퇴장하면 DB에서 완전 삭제(대화·방·숨김기록)
            const parts = _roomParticipants(roomId);
            db.all(`SELECT DISTINCT user FROM chat_hidden WHERE roomId = ?`, [roomId], (e2, hrows) => {
                const left = new Set((hrows || []).map(r => r.user));
                const bothLeft = parts.length >= 2 && parts.every(p => left.has(p));
                if (bothLeft) {
                    db.run(`DELETE FROM chats WHERE roomId = ?`, [roomId]);
                    db.run(`DELETE FROM chat_rooms WHERE roomId = ?`, [roomId]);
                    db.run(`DELETE FROM chat_hidden WHERE roomId = ?`, [roomId], () => {});
                    try { _emitToRoomUsers(roomId, 'room_closed', { roomId }); } catch (_) {}
                    return res.json({ success: true, bothLeft: true, deleted: true });
                }
                if (silent) return res.json({ success: true });
                // 상대에게만 퇴장 안내(상대는 계속 방을 볼 수 있음)
                const date = new Date().toLocaleString('ko-KR');
                const msg = '🚪 상대방이 대화방을 퇴장하셨습니다.';
                db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?, '__system__', NULL, ?, ?, ?)`, [roomId, msg, date, new Date().toISOString()], function() {
                    try { _emitToRoomUsers(roomId, 'receive_message', { roomId, sender: '__system__', message: msg, id: this.lastID, date }); } catch (_) {}
                    res.json({ success: true });
                });
            });
        });
    };
    if (roomId.startsWith('room_ord_')) {
        // 주문 대화방: 환불/구매확정 등 '종료된 거래'만 나갈 수 있음(진행 중 거래는 보호)
        const orderId = roomId.replace('room_ord_', '');
        db.get(`SELECT status, ended FROM product_orders po LEFT JOIN chat_rooms cr ON cr.roomId = ? WHERE po.id = ?`, [roomId, orderId], (e, ord) => {
            const terminal = ord && (ord.status === 'refunded' || ord.status === 'confirmed');
            const closed = ord && ord.ended === 1;
            if (terminal || closed || !ord) return _doHide(true);
            return res.status(400).json({ error: '진행 중인 주문 대화방은 나갈 수 없습니다. (환불·구매확정 후 가능)' });
        });
        return;
    }
    _doHide(false);
});

app.post('/api/deposit/request', (req, res) => { const me = requireUser(req, res); if (!me) return; const rawDate = new Date().toISOString(); db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date, rawDate) VALUES (?, ?, ?, '대기', ?, ?)`, [me, req.body.senderName, Number(req.body.amount)||0, new Date().toLocaleString('ko-KR'), rawDate], () => { res.json({ success: true }); }); });

app.post('/api/withdraw/request', (req, res) => {
    const meName = requireUser(req, res); if (!meName) return;   // ★신원=토큰
    const amount = Math.floor(Number(req.body.amount) || 0); const rawDate = new Date().toISOString();
    if (!(amount > 0)) return res.status(400).json({ error: '출금액을 확인하세요.' });
    db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [amount, meName, amount], function(e) {
        if (e || this.changes === 0) return res.status(400).json({ error: '잔액 부족' });
        db.run(`INSERT INTO withdrawals (name, amount, status, date, rawDate) VALUES (?, ?, '대기', ?, ?)`, [meName, amount, new Date().toLocaleString('ko-KR'), rawDate], () => res.json({ success: true }));
    });
});

app.get('/api/admin/actions', (req, res) => {
    if(!requireAdmin(req,res)) return;
    db.all(`SELECT d.*, u.realname, u.bank, u.account FROM deposits d LEFT JOIN users u ON d.user_name = u.name WHERE d.status = '대기'`, [], (err, deps) => {
        db.all(`SELECT w.*, u.realname, u.bank, u.account FROM withdrawals w LEFT JOIN users u ON w.name = u.name WHERE w.status = '대기'`, [], (err2, wds) => { res.json({ deposits: deps || [], withdrawals: wds || [] }); });
    });
});

app.post('/api/admin/approve', (req, res) => {
    const { type, id, userName } = req.body; const amount = Number(req.body.amount) || 0;
    if(!requireAdmin(req,res)) return;
    if(type === 'deposit_direct') {
        db.serialize(() => { db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, userName]); db.run(`UPDATE deposits SET status = '승인_증액' WHERE id = ?`, [id], () => res.json({ success: true })); });
    } else if (type === 'withdraw') { db.run(`UPDATE withdrawals SET status = '승인출금완료' WHERE id = ?`, [id], () => res.json({ success: true })); }
    else if (type === 'withdraw_reject') {
        // ↩️ 출금 거절/취소: 신청 시 즉시 차감했던 금액을 원자적으로 재크레딧 + 상태 '반려'. 상태 조건부 플립으로 1회만(이중 재크레딧 차단).
        db.get(`SELECT name, amount, status FROM withdrawals WHERE id = ?`, [id], (ge, w) => {
            if (ge) return res.status(500).json({ error: ge.message });
            if (!w) return res.status(404).json({ error: '출금 신청을 찾을 수 없습니다.' });
            db.serialize(() => {
                db.run('BEGIN IMMEDIATE');
                db.run(`UPDATE withdrawals SET status = '반려' WHERE id = ? AND status = '대기'`, [id], function(ue) {
                    if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                    if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 처리된 출금 신청입니다.' }); }
                    db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [w.amount, w.name], function(ce) {
                        if (ce) { db.run('ROLLBACK'); return res.status(500).json({ error: ce.message }); }
                        db.run('COMMIT', () => res.json({ success: true, rejected: true, recredited: w.amount }));
                    });
                });
            });
        });
    }
    else { res.status(400).json({ error: '알 수 없는 승인 유형입니다.' }); }
});

app.post('/api/transfer', (req, res) => {
    const sender = requireUser(req, res); if (!sender) return;   // ★신원=토큰(본문 sender 무시) → 타인 명의 송금 차단
    const amount = Math.floor(Number(req.body.amount) || 0);
    const receiver = String(req.body.receiver || '');
    // ★보안★ 음수/0 금지(음수 송금=역방향 탈취 방지), 자기송금 금지, 수신자 존재 확인
    if (!(amount > 0)) return res.status(400).json({ error: "송금액은 1 이상이어야 합니다." });
    if (!sender || !receiver) return res.status(400).json({ error: "보내는/받는 사람이 필요합니다." });
    if (sender === receiver) return res.status(400).json({ error: "자기 자신에게는 송금할 수 없습니다." });
    db.get(`SELECT name FROM users WHERE name = ?`, [receiver], (er, rRow) => {
        if (!rRow) return res.status(404).json({ error: "받는 사람 계정이 없습니다." });
        const rawDate = new Date().toISOString(); const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run('BEGIN IMMEDIATE');
            // 잔액 가드 원자화: balance >= amount 조건부 차감 → changes=0이면 잔액부족으로 롤백
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [amount, sender, amount], function(e2) {
                if (e2 || this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: "잔액 부족 또는 계정 오류" }); }
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, receiver]);
                db.run(`INSERT INTO transfers (sender, receiver, amount, date, rawDate) VALUES (?, ?, ?, ?, ?)`, [sender, receiver, amount, date, rawDate]);
                db.run('COMMIT', () => res.json({ success: true }));
            });
        });
    });
});

// ===================== 🔒💰 전송 파일 잠금(금액/암호) =====================
// 전송 시 sender가 금액·암호를 선택 지정 → 실제 R2 URL은 서버 보관, 수신자가 결제/암호 통과 시에만 URL 전달.
// 둘 다 미설정이면 클라가 이 API를 쓰지 않고 기존처럼 URL을 그대로 첨부(동작 동일).
app.post('/api/lockfile/create', (req, res) => {
    const owner = requireUser(req, res); if (!owner) return;
    const url = String(req.body.url || '');
    const fileName = String(req.body.fileName || 'file');
    const mime = String(req.body.mime || 'application/octet-stream');
    const size = Math.max(0, Math.floor(Number(req.body.size) || 0));
    const price = Math.max(0, Math.floor(Number(req.body.price) || 0));
    const password = req.body.password == null ? '' : String(req.body.password);
    if (!url) return res.status(400).json({ error: 'url이 필요합니다.' });
    if (price === 0 && !password) return res.status(400).json({ error: '금액 또는 암호 중 하나는 지정해야 합니다.' });
    const token = crypto.randomBytes(16).toString('hex');
    const pwHash = password ? hashPassword(password) : '';
    db.run(`INSERT INTO locked_files (token, owner, fileName, url, mime, size, price, pwHash, createdAt) VALUES (?,?,?,?,?,?,?,?,?)`,
        [token, owner, fileName, url, mime, size, price, pwHash, Date.now()], function (e) {
            if (e) return res.status(500).json({ error: '저장 실패' });
            res.json({ ok: true, token, price, hasPw: !!password });
        });
});
// 잠금 파일 메타(잠금 상태 렌더용) — URL은 절대 포함하지 않음
app.get('/api/lockfile/:token/info', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.get(`SELECT owner, fileName, mime, size, price, pwHash FROM locked_files WHERE token = ?`, [req.params.token], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '없는 파일입니다.' });
        db.get(`SELECT paid FROM locked_file_unlocks WHERE token = ? AND userName = ?`, [req.params.token, me], (e2, u) => {
            res.json({ owner: row.owner, fileName: row.fileName, mime: row.mime, size: row.size, price: row.price, hasPw: !!row.pwHash, isOwner: row.owner === me, unlocked: (row.owner === me) || !!u });
        });
    });
});
// 잠금 해제(암호 검증 + 금액 결제) → 성공 시 실제 URL 전달. 이미 해제한 사용자는 재결제 없이 재발급.
app.post('/api/lockfile/:token/open', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const token = req.params.token;
    const password = req.body.password == null ? '' : String(req.body.password);
    db.get(`SELECT * FROM locked_files WHERE token = ?`, [token], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '없는 파일입니다.' });
        const done = () => res.json({ ok: true, url: row.url, fileName: row.fileName, mime: row.mime, size: row.size });
        if (row.owner === me) return done();   // 소유자는 무료
        db.get(`SELECT paid FROM locked_file_unlocks WHERE token = ? AND userName = ?`, [token, me], (e2, u) => {
            if (u) return done();   // 이미 해제(결제)함 → 재발급
            if (row.pwHash && !verifyPassword(password, row.pwHash)) return res.status(403).json({ error: '암호가 일치하지 않습니다.', needPw: true });
            if (row.price > 0) {
                const rawDate = new Date().toISOString(); const date = new Date().toLocaleString('ko-KR');
                db.serialize(() => {
                    db.run('BEGIN IMMEDIATE');
                    db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [row.price, me, row.price], function (ue) {
                        if (ue || this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '잔액이 부족합니다.', needPay: true, price: row.price }); }
                        db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.price, row.owner]);
                        db.run(`INSERT INTO transfers (sender, receiver, amount, date, rawDate) VALUES (?, ?, ?, ?, ?)`, [me, row.owner, row.price, date, rawDate]);
                        db.run(`INSERT OR IGNORE INTO locked_file_unlocks (token, userName, at, paid) VALUES (?,?,?,1)`, [token, me, Date.now()]);
                        db.run('COMMIT', () => done());
                    });
                });
            } else {
                db.run(`INSERT OR IGNORE INTO locked_file_unlocks (token, userName, at, paid) VALUES (?,?,?,0)`, [token, me, Date.now()], () => done());
            }
        });
    });
});

// ☁️ 클라우드 저장 용량 (Earth 지갑 결제) — 100MB 무료, 500GB당 3만원(= GB당 60원)
const CLOUD_FREE_BYTES = 100 * 1024 * 1024;
const CLOUD_PRICE_PER_GB = 60;
app.get('/api/cloud/usage/:name', (req, res) => {
    db.get(`SELECT purchasedBytes, usedBytes FROM cloud_storage WHERE name = ?`, [req.params.name], (err, row) => {
        const purchased = (row && row.purchasedBytes) || 0;
        const used = (row && row.usedBytes) || 0;
        res.json({ freeBytes: CLOUD_FREE_BYTES, purchasedBytes: purchased, quotaBytes: CLOUD_FREE_BYTES + purchased, usedBytes: used, pricePerGB: CLOUD_PRICE_PER_GB });
    });
});
app.post('/api/cloud/purchase', (req, res) => {
    const name = requireUser(req, res); if (!name) return;   // ★신원=토큰
    const gb = Number(req.body.gb) || 0;
    if (!name || gb <= 0) return res.status(400).json({ error: '구매할 용량(GB)을 확인하세요' });
    const price = Math.round(gb * CLOUD_PRICE_PER_GB);
    const addBytes = Math.round(gb * 1024 * 1024 * 1024);
    const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
    // 원자적 잔액 차감(BEGIN IMMEDIATE + balance>=? 조건부 + changes 가드) → /api/transfer와 동일 패턴. 스토리지 크레딧도 같은 트랜잭션 안에서 처리.
    db.serialize(() => {
        db.run('BEGIN IMMEDIATE');
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [price, name, price], function(ue) {
            if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
            if (this.changes === 0) {
                db.run('ROLLBACK');
                return db.get(`SELECT balance FROM users WHERE name = ?`, [name], (e2, u) => {
                    if (!u) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
                    const bal = u.balance || 0;
                    res.status(400).json({ error: `지갑 잔액 부족 (필요 ${price.toLocaleString()}원 / 보유 ${bal.toLocaleString()}원)`, insufficient: true, need: price, balance: bal, shortfall: price - bal });
                });
            }
            db.run(`INSERT INTO cloud_storage (name, purchasedBytes, usedBytes) VALUES (?, ?, 0) ON CONFLICT(name) DO UPDATE SET purchasedBytes = purchasedBytes + ?`, [name, addBytes, addBytes]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date, rawDate) VALUES (?, ?, ?, ?, ?)`, [name, 'RAYCloud 스토리지 충전', price, date, rawDate]);
            db.run('COMMIT', () => {
                db.get(`SELECT balance FROM users WHERE name = ?`, [name], (e3, u2) => {
                    db.get(`SELECT purchasedBytes FROM cloud_storage WHERE name = ?`, [name], (e2, row) => {
                        const purchased = (row && row.purchasedBytes) || 0;
                        res.json({ success: true, price: price, addedGB: gb, balance: (u2 && u2.balance) || 0, quotaBytes: CLOUD_FREE_BYTES + purchased });
                    });
                });
            });
        });
    });
});
app.post('/api/cloud/usage', (req, res) => {
    const name = req.body.name; const usedBytes = Math.max(0, Number(req.body.usedBytes) || 0);
    if (!name) return res.status(400).json({ error: 'name 누락' });
    db.run(`INSERT INTO cloud_storage (name, purchasedBytes, usedBytes) VALUES (?, 0, ?) ON CONFLICT(name) DO UPDATE SET usedBytes = ?`, [name, usedBytes, usedBytes], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ===================== ☁️ [항목5] 로컬 공유폴더 R2 미러 백업(유료 옵션) =====================
// 원하는 사용자만 클라우드 지갑(cloud_storage, GB당 60원)으로 결제해 공유폴더 파일을 R2에 백업.
// 원본 손실(디스크 고장) 대비 클라우드 사본. 업로드=브라우저→R2 프리사인 PUT(무료 egress), 복원=프리사인 GET.
function _mirrorKey(user, rpath) { return 'mirror/' + crypto.createHash('sha1').update(user + '|' + rpath).digest('hex'); }
function _mirrorUsage(name, cb) {   // cb(err, {used, quota, purchased, enabled})
    db.get(`SELECT COALESCE(SUM(size),0) AS used FROM mirror_files WHERE userName = ?`, [name], (e, r) => {
        if (e) return cb(e);
        db.get(`SELECT purchasedBytes FROM cloud_storage WHERE name = ?`, [name], (e2, c) => {
            db.get(`SELECT enabled FROM mirror_prefs WHERE userName = ?`, [name], (e3, p) => {
                const purchased = (c && c.purchasedBytes) || 0;
                cb(null, { used: (r && r.used) || 0, purchased, quota: CLOUD_FREE_BYTES + purchased, enabled: !!(p && p.enabled) });
            });
        });
    });
}
app.get('/api/mirror/status', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    _mirrorUsage(name, (e, u) => { if (e) return res.status(500).json({ error: e.message }); res.json(Object.assign({ freeBytes: CLOUD_FREE_BYTES, pricePerGB: CLOUD_PRICE_PER_GB, r2: !!_r2 }, u)); });
});
app.post('/api/mirror/enable', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    const on = req.body.on ? 1 : 0;
    db.run(`INSERT INTO mirror_prefs (userName, enabled) VALUES (?, ?) ON CONFLICT(userName) DO UPDATE SET enabled = ?`, [name, on, on], (e) => {
        if (e) return res.status(500).json({ error: e.message });
        res.json({ ok: true, enabled: !!on });
    });
});
app.post('/api/mirror/upload-url', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const rpath = String(req.body.rpath || ''); const size = Math.max(0, Math.floor(Number(req.body.size) || 0)); const mime = String(req.body.mime || 'application/octet-stream');
    if (!rpath) return res.status(400).json({ error: 'rpath 필요' });
    _mirrorUsage(name, (e, u) => {
        if (e) return res.status(500).json({ error: e.message });
        db.get(`SELECT size FROM mirror_files WHERE userName = ? AND rpath = ?`, [name, rpath], (e2, ex) => {
            const usedExcl = u.used - ((ex && ex.size) || 0);
            if (usedExcl + size > u.quota) return res.status(402).json({ error: '클라우드 용량이 부족합니다. 용량을 구매하세요.', need: (usedExcl + size) - u.quota, quota: u.quota, used: usedExcl });
            try {
                const { PutObjectCommand } = require('@aws-sdk/client-s3');
                const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
                const key = _mirrorKey(name, rpath);
                getSignedUrl(_r2.client, new PutObjectCommand({ Bucket: _r2.bucket, Key: key, ContentType: mime }), { expiresIn: 3600 })
                    .then(url => res.json({ url, key })).catch(err => res.status(500).json({ error: err.message }));
            } catch (err) { res.status(500).json({ error: err.message }); }
        });
    });
});
app.post('/api/mirror/commit', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    const rpath = String(req.body.rpath || ''); const key = String(req.body.key || '');
    const size = Math.max(0, Math.floor(Number(req.body.size) || 0)); const mime = String(req.body.mime || ''); const mtime = Math.floor(Number(req.body.mtime) || Date.now());
    if (!rpath || key !== _mirrorKey(name, rpath)) return res.status(400).json({ error: '잘못된 요청' });
    db.run(`INSERT INTO mirror_files (userName, rpath, key, size, mime, mtime) VALUES (?,?,?,?,?,?) ON CONFLICT(userName, rpath) DO UPDATE SET key=?, size=?, mime=?, mtime=?`,
        [name, rpath, key, size, mime, mtime, key, size, mime, mtime], (e) => {
            if (e) return res.status(500).json({ error: e.message });
            _mirrorUsage(name, (e2, u) => res.json({ ok: true, used: u ? u.used : 0, quota: u ? u.quota : 0 }));
        });
});
app.get('/api/mirror/list', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    db.all(`SELECT rpath, key, size, mime, mtime FROM mirror_files WHERE userName = ? ORDER BY mtime DESC`, [name], (e, rows) => {
        if (e) return res.status(500).json({ error: e.message });
        res.json({ items: rows || [] });
    });
});
app.post('/api/mirror/download-url', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    if (!_r2) return res.status(400).json({ error: 'R2 미설정' });
    const rpath = String(req.body.rpath || '');
    db.get(`SELECT key, mime FROM mirror_files WHERE userName = ? AND rpath = ?`, [name, rpath], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '없는 파일' });
        try {
            const { GetObjectCommand } = require('@aws-sdk/client-s3');
            const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
            getSignedUrl(_r2.client, new GetObjectCommand({ Bucket: _r2.bucket, Key: row.key }), { expiresIn: 3600 })
                .then(url => res.json({ url, mime: row.mime })).catch(err => res.status(500).json({ error: err.message }));
        } catch (err) { res.status(500).json({ error: err.message }); }
    });
});
app.post('/api/mirror/delete', (req, res) => {
    const name = requireUser(req, res); if (!name) return;
    const rpath = String(req.body.rpath || '');
    db.get(`SELECT key FROM mirror_files WHERE userName = ? AND rpath = ?`, [name, rpath], (e, row) => {
        if (!row) return res.json({ ok: true });
        db.run(`DELETE FROM mirror_files WHERE userName = ? AND rpath = ?`, [name, rpath], () => {
            if (_r2) { try { const { DeleteObjectCommand } = require('@aws-sdk/client-s3'); _r2.client.send(new DeleteObjectCommand({ Bucket: _r2.bucket, Key: row.key })).catch(() => {}); } catch (_) {} }
            res.json({ ok: true });
        });
    });
});

// ===================== 🔗 비회원 외부 공유(QR + 웹링크) =====================
// Earth 미가입 고객에게 파일 전달: 회원이 링크 생성 → 메일/메신저로 QR+링크 전송 → 고객이 랜딩페이지에서 가입안내 + 공유폴더 다운로드.
app.post('/api/guestshare/create', (req, res) => {
    const owner = requireUser(req, res); if (!owner) return;
    const url = String(req.body.url || ''); const fileName = String(req.body.fileName || 'file');
    const mime = String(req.body.mime || 'application/octet-stream'); const size = Math.max(0, Math.floor(Number(req.body.size) || 0));
    const days = Math.min(90, Math.max(1, Math.floor(Number(req.body.days) || 14)));
    if (!/^https?:\/\//i.test(url)) return res.status(400).json({ error: '공개 URL이 필요합니다.' });
    const token = crypto.randomBytes(9).toString('base64url');
    const now = Date.now(); const expiresAt = now + days * 86400000;
    db.run(`INSERT INTO guest_shares (token, owner, fileName, url, mime, size, createdAt, expiresAt, downloads) VALUES (?,?,?,?,?,?,?,?,0)`,
        [token, owner, fileName, url, mime, size, now, expiresAt], function (e) {
            if (e) return res.status(500).json({ error: '저장 실패' });
            res.json({ ok: true, token, link: _shareBaseUrl(req) + '/s/' + token, expiresAt });
        });
});
app.get('/api/guestshare/:token', (req, res) => {
    db.get(`SELECT owner, fileName, mime, size, url, expiresAt FROM guest_shares WHERE token = ?`, [req.params.token], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '없는 공유입니다.' });
        if (row.expiresAt && Date.now() > row.expiresAt) return res.json({ expired: true, fileName: row.fileName });
        // 발신자 프로필/브랜드(로고) 동봉 → 랜딩에서 신뢰감 있게 표시
        db.get(`SELECT profilePic, realname FROM users WHERE name = ?`, [row.owner], (e2, u) => {
            db.get(`SELECT name, logo FROM stores WHERE owner = ? ORDER BY rowid LIMIT 1`, [row.owner], (e3, st) => {
                res.json({
                    fileName: row.fileName, mime: row.mime, size: row.size, url: row.url, owner: row.owner, expiresAt: row.expiresAt,
                    ownerPic: (u && u.profilePic) || '', ownerReal: (u && u.realname) || '',
                    brand: (st && st.name) || '', brandLogo: (st && st.logo) || ''
                });
            });
        });
    });
});
app.get('/s/:token/dl', (req, res) => {
    db.get(`SELECT url, expiresAt FROM guest_shares WHERE token = ?`, [req.params.token], (e, row) => {
        if (e || !row) return res.status(404).send('없는 공유입니다.');
        if (row.expiresAt && Date.now() > row.expiresAt) return res.status(410).send('만료된 공유입니다.');
        db.run(`UPDATE guest_shares SET downloads = downloads + 1 WHERE token = ?`, [req.params.token]);
        res.redirect(row.url);   // R2(Cloudflare) 직접 다운로드 — egress 무료
    });
});
// 로그인/가입한 사용자가 외부공유를 '수령' → 발신자와의 채팅방에 파일 메시지를 넣어 일반 채팅 전송과 동일한 흐름으로(수신 시 공유폴더 자동저장) 이어지게 함.
app.post('/api/guestshare/:token/claim', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.get(`SELECT owner, fileName, url, mime, size, expiresAt FROM guest_shares WHERE token = ?`, [req.params.token], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '없는 공유입니다.' });
        if (row.expiresAt && Date.now() > row.expiresAt) return res.status(410).json({ error: '만료된 공유입니다.' });
        if (row.owner === me) return res.json({ ok: true, self: true });
        const roomId = 'room_msg_' + [row.owner, me].sort().join('_');
        const sizeKB = Math.round((row.size || 0) / 1024);
        const msg = '[FILE_ATTACH]' + row.fileName + '|' + sizeKB + '|' + (row.mime || '') + '|' + row.url;
        const date = new Date().toLocaleString('ko-KR');
        db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [row.owner, me]);
        db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [me, row.owner]);
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?,?,?,?,?,?)`, [roomId, row.owner, null, msg, date, new Date().toISOString()], function () {
            const payload = { roomId, sender: row.owner, message: msg, id: this.lastID, date };
            try { _emitToRoomUsers(roomId, 'receive_message', payload); } catch (_) {}
            db.run(`UPDATE guest_shares SET downloads = downloads + 1 WHERE token = ?`, [req.params.token]);
            res.json({ ok: true, roomId, owner: row.owner, fileName: row.fileName });
        });
    });
});
function _guestLandingHtml(token) {
    const t = JSON.stringify(String(token));
    return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Earth 파일 받기</title><link rel="icon" href="/icon-192.png">
<style>
 :root{--bg:#f5f6f8;--card:#fff;--tx:#0f172a;--sub:#64748b;--pri:#2563eb;--line:#e8eaee}
 *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font-family:'Pretendard',-apple-system,BlinkMacSystemFont,system-ui,'Malgun Gothic',sans-serif;-webkit-font-smoothing:antialiased}
 .wrap{max-width:480px;margin:0 auto;padding:24px 18px 48px}
 .brand{display:flex;align-items:center;gap:8px;font-weight:800;font-size:15px;color:var(--pri);margin-bottom:18px}
 .brand .dot{width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,#2563eb,#7c3aed);display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 4px 24px rgba(15,23,42,.06)}
 .fileicon{width:64px;height:64px;border-radius:16px;background:#eef2ff;color:var(--pri);display:flex;align-items:center;justify-content:center;font-size:30px;margin-bottom:14px}
 .fn{font-size:18px;font-weight:800;word-break:break-all;line-height:1.35}
 .meta{font-size:13px;color:var(--sub);margin-top:4px}
 .sender{display:flex;align-items:center;gap:10px;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid var(--line)}
 .avatar{width:46px;height:46px;border-radius:50%;background:#eef2ff;flex:none;display:flex;align-items:center;justify-content:center;font-size:19px;color:var(--pri);font-weight:800;overflow:hidden}
 .avatar img{width:100%;height:100%;object-fit:cover}
 .sender .nm{font-weight:800;font-size:14px;line-height:1.3}
 .sender .br{font-size:12px;color:var(--sub);margin-top:1px}
 .prev{margin:16px 0;border-radius:14px;overflow:hidden;border:1px solid var(--line);max-height:300px;display:none;cursor:zoom-in;position:relative}
 .prev img{width:100%;display:block}
 .prev .zoom{position:absolute;right:8px;bottom:8px;background:rgba(15,23,42,.7);color:#fff;font-size:11px;padding:4px 8px;border-radius:8px}
 .lb{position:fixed;inset:0;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;z-index:100;padding:14px}
 .lb.show{display:flex}
 .lb img{max-width:100%;max-height:100%;border-radius:8px}
 .lb .x{position:absolute;top:14px;right:16px;color:#fff;font-size:30px;cursor:pointer;line-height:1}
 .btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:15px;border-radius:12px;font-weight:800;font-size:15px;cursor:pointer;border:none;margin-top:10px;text-decoration:none}
 .btn.p{background:var(--pri);color:#fff}.btn.o{background:#fff;color:var(--tx);border:1px solid #cbd5e1}
 .join{margin-top:22px;background:linear-gradient(135deg,#eef2ff,#faf5ff);border:1px solid #e5e7fb;border-radius:16px;padding:18px}
 .join h3{margin:0 0 6px;font-size:15px}.join p{margin:0 0 12px;font-size:13px;color:var(--sub);line-height:1.5}
 .exp{text-align:center;font-size:12px;color:#94a3b8;margin-top:18px}
 .err{text-align:center;padding:40px 10px;color:#64748b}
</style></head><body>
<div class="wrap">
 <div class="brand"><span class="dot">E</span> Earth</div>
 <div id="app" class="card"><div class="err">불러오는 중…</div></div>
 <div class="exp" id="exp"></div>
</div>
<div class="lb" id="lb"><span class="x">✕</span><img src="" alt=""></div>
<script>
 var TOKEN=${t};
 (function(){ var lb=document.getElementById('lb'); if(lb){ lb.addEventListener('click',function(e){ if(e.target===lb || e.target.className==='x') lb.classList.remove('show'); }); document.addEventListener('keydown',function(e){ if(e.key==='Escape') lb.classList.remove('show'); }); } })();
 function fmt(b){b=Number(b)||0;if(b>=1073741824)return (b/1073741824).toFixed(2)+'GB';if(b>=1048576)return (b/1048576).toFixed(1)+'MB';if(b>=1024)return (b/1024).toFixed(0)+'KB';return b+'B';}
 function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
 (async function(){
   var app=document.getElementById('app');
   try{
     var r=await fetch('/api/guestshare/'+encodeURIComponent(TOKEN)); var d=await r.json();
     if(!r.ok || d.expired){ app.innerHTML='<div class="err"><div style="font-size:40px">⌛</div><b>'+(d.expired?'만료된 공유입니다.':'존재하지 않는 공유입니다.')+'</b><div style="margin-top:6px;font-size:13px">보낸 분께 다시 요청해 주세요.</div></div>'; return; }
     var isImg=/^image\\//.test(d.mime||'');
     var dl='/s/'+encodeURIComponent(TOKEN)+'/dl';
     var claimUrl='/?claim='+encodeURIComponent(TOKEN);
     var av=d.brandLogo||d.ownerPic||'';
     var avHtml=av?('<span class="avatar"><img src="'+esc(av)+'" alt=""></span>'):('<span class="avatar">'+esc((d.owner||'?').slice(0,1))+'</span>');
     var title=d.brand||d.owner||'보낸 사람';
     var sub=d.brand?('보낸 사람 · '+esc(d.owner||'')):(d.ownerReal?esc(d.ownerReal)+'님이 보냄':'회원이 보냄');
     app.innerHTML=
       '<div class="sender">'+avHtml+'<div><div class="nm">'+esc(title)+'</div><div class="br">'+sub+'</div></div></div>'
       +'<div class="fileicon">'+(isImg?'🖼️':'📄')+'</div>'
       +'<div class="fn">'+esc(d.fileName)+'</div>'
       +'<div class="meta">'+fmt(d.size)+(isImg?' · 눌러서 크게 보기':'')+'</div>'
       +'<div class="prev" id="prev"'+(isImg?' style="display:block"':'')+'>'+(isImg?'<img src="'+esc(d.url)+'" alt=""><span class="zoom">🔍 크게 보기</span>':'')+'</div>'
       +'<a class="btn p" href="'+claimUrl+'">📥 Earth에서 받기 (공유폴더 자동저장)</a>'
       +'<a class="btn o" href="'+dl+'">⬇️ 로그인 없이 바로 다운로드</a>'
       +'<div class="join"><h3>🌍 Earth로 받으면?</h3><p>가입/로그인하면 이 파일이 보낸 분과의 <b>채팅방으로 전달</b>되어 지정한 <b>공유폴더에 자동 저장</b>됩니다. 이후 채팅·대용량 전송·백업까지 그대로 쓸 수 있어요. "바로 다운로드"는 가입 없이 파일만 내려받습니다.</p></div>';
     if(isImg){ var pv=document.getElementById('prev'); if(pv) pv.onclick=function(){ var lb=document.getElementById('lb'); lb.querySelector('img').src=d.url; lb.classList.add('show'); }; }
     if(d.expiresAt){ document.getElementById('exp').textContent='이 링크는 '+new Date(d.expiresAt).toLocaleDateString('ko-KR')+'까지 유효합니다.'; }
   }catch(e){ app.innerHTML='<div class="err">불러오지 못했습니다. 잠시 후 다시 시도해 주세요.</div>'; }
 })();
</script></body></html>`;
}
app.get('/s/:token', (req, res) => { res.type('html').send(_guestLandingHtml(req.params.token)); });

// 🦷 [기공소] 기본 보철 품목/수가 시드(상점이 편집 가능). tab: general(일반보철·임플란트)/denture(덴처)/ortho(교정)
function _defaultRxItems() {
    return [
        { tab:'general', category:'임플란트', name:'Implant PFM Crown(직접인상)', price:60000, pontic:50000 },
        { tab:'general', category:'임플란트', name:'Implant PFM Crown(보험)+기성ABT/밀링&지그', price:90000, pontic:0 },
        { tab:'general', category:'임플란트', name:'Implant Full Zirconia Crown+커스텀 어버트먼트', price:90000, pontic:40000 },
        { tab:'general', category:'프렙', name:'PFM Crown', price:45000, pontic:40000 },
        { tab:'general', category:'프렙', name:'지르코니아 크라운', price:60000, pontic:50000 },
        { tab:'general', category:'프렙', name:'풀지르코니아 임플란트 크라운(전치)', price:70000, pontic:0 },
        { tab:'general', category:'프렙', name:'골드크라운(A type)', price:25000, pontic:20000 },
        { tab:'general', category:'프렙', name:'인레이/온레이(골드)', price:25000, pontic:0 },
        { tab:'general', category:'프렙', name:'세라믹 인레이/온레이', price:35000, pontic:0 },
        { tab:'general', category:'프렙', name:'라미네이트', price:60000, pontic:0 },
        { tab:'general', category:'기타', name:'서지컬 가이드', price:500000, pontic:0 },
        { tab:'general', category:'기타', name:'임시치아(템포러리)', price:5000, pontic:0 },
        { tab:'general', category:'기타', name:'커스텀 어버트먼트', price:40000, pontic:0 },
        { tab:'denture', category:'덴처', name:'레진 총의치(Full Denture)', price:250000, pontic:0 },
        { tab:'denture', category:'덴처', name:'메탈 부분의치(Metal Partial Denture)', price:300000, pontic:0 },
        { tab:'denture', category:'덴처', name:'클래스프(Clasp) 추가', price:20000, pontic:0 },
        { tab:'denture', category:'덴처', name:'릴라인(Reline)', price:50000, pontic:0 },
        { tab:'denture', category:'덴처', name:'리베이스(Rebase)', price:70000, pontic:0 },
        { tab:'denture', category:'덴처', name:'의치 수리(Repair)', price:30000, pontic:0 },
        { tab:'ortho', category:'교정', name:'투명교정 장치(1단계)', price:50000, pontic:0 },
        { tab:'ortho', category:'교정', name:'투명 리테이너', price:30000, pontic:0 },
        { tab:'ortho', category:'교정', name:'하와이안 리테이너', price:35000, pontic:0 },
        { tab:'ortho', category:'교정', name:'확장장치(Expansion)', price:80000, pontic:0 },
        { tab:'ortho', category:'교정', name:'리테이너 수리', price:20000, pontic:0 }
    ];
}
app.post('/api/store/create', (req, res) => {
    db.get(`SELECT id FROM stores WHERE name = ?`, [req.body.name], (err, row) => {
        if (row) return res.status(400).json({ error: "이미 존재하는 명칭의 상점입니다." });
        const category = req.body.category || 'general';
        const bizType = req.body.bizType === 'individual' ? 'individual' : 'business';
        const bizNo = String(req.body.bizNo || '').replace(/\D/g, '');
        const storeId = 'STR_' + Date.now();
        // 🦷 기공소: 취급 품목/수가 시드(요청 body의 rxItems가 있으면 사용, 없으면 기본 시드)
        const isLab = (category === 'dental_lab');
        let rxItems = null;
        if (isLab) { try { rxItems = Array.isArray(req.body.rxItems) && req.body.rxItems.length ? req.body.rxItems : _defaultRxItems(); } catch (_) { rxItems = _defaultRxItems(); } }
        db.run(`INSERT INTO stores (id, name, owner, logo, status, background, description, category, bizType, bizNo, rx_items) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)`,
            [storeId, req.body.name, req.body.owner, req.body.logo, req.body.background || '', req.body.description || '', category, bizType, bizNo, rxItems ? JSON.stringify(rxItems) : null],
            () => {
                // 🦷 기공소 상점: '의뢰서 작성' 기본 상품 자동 등록(가격 미정=0, rx_form=1). 별도 주문서 없이 간편/상세 의뢰서로 주문.
                if (isLab) {
                    db.run(`INSERT INTO products (id, storeId, type, name, description, price_stream, price_original, seller, rx_form) VALUES (?, ?, 'html_enc', ?, ?, 0, 0, ?, 1)`,
                        ['PRD_' + Date.now(), storeId, '의뢰서 작성 (간편/상세)', '치과 기공 의뢰서를 작성하여 주문합니다. 상세 의뢰서는 취급 품목 수가로 금액이 자동 산정됩니다.', req.body.owner], () => {});
                }
                res.json({ success: true, storeId });
            });
    });
});

// 🚀 상점 배경/소개/카테고리 업데이트
app.post('/api/store/update', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰(본문 owner 무시)
    db.get(`SELECT owner FROM stores WHERE id = ?`, [req.body.id], (err, row) => {
        if(!row) return res.status(404).json({ error: "상점이 존재하지 않습니다." });
        if(row.owner !== me && !isAdminName(me)) return res.status(403).json({ error: "본인 상점만 수정 가능합니다." });
        const fields = []; const values = [];
        if(req.body.background !== undefined) { fields.push('background = ?'); values.push(req.body.background); }
        if(req.body.description !== undefined) { fields.push('description = ?'); values.push(req.body.description); }
        if(req.body.logo !== undefined && req.body.logo) { fields.push('logo = ?'); values.push(req.body.logo); }
        if(req.body.category !== undefined) { fields.push('category = ?'); values.push(req.body.category); }
        // 🧾 브랜드 편집: 상호(name)·구분(bizType)·번호(bizNo)도 수정 가능
        if(req.body.name !== undefined && String(req.body.name).trim()) { fields.push('name = ?'); values.push(String(req.body.name).trim()); }
        if(req.body.bizType !== undefined) { fields.push('bizType = ?'); values.push(req.body.bizType === 'individual' ? 'individual' : 'business'); }
        if(req.body.bizNo !== undefined) { fields.push('bizNo = ?'); values.push(String(req.body.bizNo || '').replace(/\D/g, '')); }
        if(fields.length === 0) return res.json({ success: true });
        values.push(req.body.id);
        db.run(`UPDATE stores SET ${fields.join(', ')} WHERE id = ?`, values, () => res.json({ success: true }));
    });
});

app.get('/api/stores/owned/:owner', (req, res) => { db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => res.json(rows || [])); });
app.post('/api/store/status', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰
    db.get(`SELECT owner FROM stores WHERE id = ?`, [req.body.id], (e, row) => {
        if (!row) return res.status(404).json({ error: '상점이 존재하지 않습니다.' });
        if (row.owner !== me && !isAdminName(me)) return res.status(403).json({ error: '본인 상점만 변경 가능합니다.' });
        db.run(`UPDATE stores SET status = ? WHERE id = ?`, [req.body.status, req.body.id], () => res.json({ success: true }));
    });
});

// 🚀 [v7p4] 상점 카테고리 변경 (본인 상점만)
app.post('/api/store/category', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰(본문 owner 무시)
    const { id, category } = req.body;
    if(!id || !category) return res.status(400).json({ error: 'id, category 필수' });
    db.get(`SELECT owner FROM stores WHERE id = ?`, [id], (err, row) => {
        if(err || !row) return res.status(404).json({ error: '상점을 찾을 수 없음' });
        if(row.owner !== me && !isAdminName(me)) return res.status(403).json({ error: '본인 상점만 수정 가능' });
        db.run(`UPDATE stores SET category = ? WHERE id = ?`, [category, id], (uerr) => uerr ? res.status(500).json({ error: uerr.message }) : res.json({ success: true }));
    });
});
app.get('/api/stores/active', (req, res) => { db.all(`SELECT * FROM stores WHERE status = 'active'`, [], (err, rows) => res.json(rows || [])); });
// 🚀 단일 상점 상세 (배경/소개 포함)
app.get('/api/store/:id', (req, res) => { db.get(`SELECT * FROM stores WHERE id = ?`, [req.params.id], (err, row) => res.json(row || {})); });

// 🚀 디지털 거래소 메인 쇼케이스: 최신 등록 브랜드 + 각 브랜드의 최신 상품 4개 썸네일
app.get('/api/stores/showcase', (req, res) => {
    db.all(`SELECT * FROM stores WHERE status = 'active' ORDER BY id DESC LIMIT 30`, [], (err, stores) => {
        if(err || !stores) return res.json([]);
        if(stores.length === 0) return res.json([]);
        const tasks = stores.map(st => new Promise(resolve => {
            db.all(`SELECT id, name, thumbnail, price_stream, price_original FROM products WHERE storeId = ? ORDER BY id DESC LIMIT 4`, [st.id], (e, prods) => {
                resolve({ ...st, latestProducts: prods || [], productCount: (prods || []).length });
            });
        }));
        Promise.all(tasks).then(results => {
            // 🚀 상품이 있는 브랜드를 우선 노출, 그 다음 빈 브랜드
            results.sort((a, b) => {
                if((b.latestProducts.length > 0) !== (a.latestProducts.length > 0)) {
                    return (b.latestProducts.length > 0) ? 1 : -1;
                }
                return 0; // 이미 id DESC 정렬됨
            });
            res.json(results);
        }).catch(() => res.json([]));
    });
});

app.post('/api/store/close', (req, res) => { db.serialize(() => { db.run(`DELETE FROM products WHERE storeId = ? AND seller = ?`, [req.body.id, req.body.owner]); db.run(`DELETE FROM stores WHERE id = ? AND owner = ?`, [req.body.id, req.body.owner], () => res.json({ success: true })); }); });
app.post('/api/admin/store/close', (req, res) => { 
    if(!requireAdmin(req,res)) return;
    db.serialize(() => { db.run(`DELETE FROM products WHERE storeId = ?`, [req.body.id]); db.run(`DELETE FROM stores WHERE id = ?`, [req.body.id], () => res.json({ success: true })); }); 
});

app.post('/api/products/encrypt-build', (req, res) => {
    try {
        const payloadBuffer = Buffer.from(req.body.encryptedPayload || '', 'utf-8');
        let ratio = 0;
        try {
            const compressed = zlib.deflateSync(payloadBuffer);
            ratio = Math.round((1 - (compressed.length / payloadBuffer.length)) * 100);
            if (ratio < 0 || isNaN(ratio)) ratio = Math.floor(Math.random() * 5) + 80; 
        } catch(e) { ratio = 85; }

        const block_hash = crypto.createHash('sha256').update(payloadBuffer).digest('hex');
        const sign = crypto.createSign('SHA256'); sign.update(block_hash);
        const ecc_signature = sign.sign(privateKey, 'hex');
        
        const pid = req.body.storeId.startsWith('room_msg_') ? req.body.storeId + '_' + Date.now() : 'PRD_' + Date.now();
        const isPackage = req.body.is_package ? 1 : 0;
        const packageData = req.body.package_data || null;
        // 🔗 링크 상품: 홈페이지 주소는 관리자(세션 토큰)만 등록 가능. 비관리자가 보내면 무시.
        const linkUrl = (req.body.link_url && isAdminName(authUser(req))) ? String(req.body.link_url).trim() : null;

        db.run(`INSERT INTO products (id, storeId, type, name, description, price_stream, price_original, stream_time, stream_unit, seller, thumbnail, encryptedPayload, compression_ratio, block_hash, ecc_signature, package_data, is_package, link_url) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [pid, req.body.storeId, req.body.name, req.body.description, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, Number(req.body.stream_time)||0, req.body.stream_unit, req.body.seller, req.body.thumbnail, req.body.encryptedPayload, ratio, block_hash, ecc_signature, packageData, isPackage, linkUrl], function(err) {
                if(err) return res.status(500).json({error: err.message});
                res.json({ success: true, id: pid, ratio, block_hash, ecc_signature });
            });
    } catch(err) { res.status(500).json({error: "상품 패키징 실패"}); }
});

// 🚀 구매 확정 시 작성된 폼 데이터 + 첨부 파일을 판매자에게 채팅으로 전달
// 🚀 [v6] 주문서 제출 (구매 확정 X → 'pending' 상태로 판매자 승인 대기)
app.post('/api/product/submit-order', (req, res) => {
    const { productId, buyer, seller, bundle_html, memo, form_data, pdf_filled_data, buyer_info, status } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    const ordStatus = status || 'pending'; // 기본은 pending
    // 💳 결제수단(구매자 선택). 카드면 주문 시점에 PG 승인(외부 카드 캡처) → 승인 실패 시 주문 거부.
    const method = req.body.payMethod === 'card' ? 'card' : 'balance';
    // 🔒 금액 서버검증: 일반 상품은 클라이언트 amount를 무시하고 서버 상품가(price_original||price_stream)로 강제(1원 주문 방지).
    //    기공소 의뢰서(rx_form=1)는 재견적/자동산정 금액이므로 전송값 유지.
    db.get(`SELECT rx_form, price_original, price_stream FROM products WHERE id = ?`, [productId], (pe, prod) => {
        if (pe) return res.status(500).json({ error: pe.message });
        let amount = Number(req.body.amount) || 0;
        if (prod && !prod.rx_form) amount = Number(prod.price_original) || Number(prod.price_stream) || 0;
        let pgApproval = null;
        if (method === 'card' && amount > 0) {
            const auth = _pgAuthorize({ payer: buyer, amount, method: 'card', cardPw: req.body.cardPw });
            if (!auth.ok) return res.status(400).json({ error: '카드 승인 실패: ' + (auth.error || '') });
            pgApproval = auth.approvalNo;
        }
        db.run(`INSERT INTO product_orders (productId, buyer, seller, bundle_html, memo, form_data, pdf_filled_data, buyer_info, status, amount, created_at, pay_method, pg_approval) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [productId, buyer, seller, bundle_html || '', memo || '', JSON.stringify(form_data || {}), pdf_filled_data || '', JSON.stringify(buyer_info || {}), ordStatus, amount || 0, date, method, pgApproval],
            function(err) {
                if(err) return res.status(500).json({ error: err.message });
                res.json({ success: true, orderId: this.lastID, payMethod: method, approvalNo: pgApproval, amount });
            });
    });
});

// 💬 [채팅 상태알림] 주문 상태가 바뀔 때 구매자·판매자 채팅방에 시스템 메시지 기록 + order_status 이벤트(카드 갱신용) 방출.
function _orderRoomId(orderId) { return 'room_ord_' + orderId; }   // 💬 주문별 고유 대화방 id
function _notifyOrderStatus(buyer, seller, orderId, status, msg) {
    try {
        const roomId = _orderRoomId(orderId);
        _setOrderRoom(roomId, buyer, seller);   // 참가자 캐시 보강(소켓 전송용)
        if (msg) {
            const date = new Date().toLocaleString('ko-KR');
            db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?, '__system__', NULL, ?, ?, ?)`, [roomId, msg, date, new Date().toISOString()], function() {
                try { _emitToRoomUsers(roomId, 'receive_message', { roomId, sender: '__system__', message: msg, id: this.lastID, date }); } catch (_) {}
            });
        }
        try { _emitToRoomUsers(roomId, 'order_status', { orderId, status, buyer, seller }); } catch (_) {}   // 채팅 주문카드 실시간 갱신
    } catch (_) {}
}
// 💬 구매확정 시 해당 주문 대화방 종료(목록에서 사라짐). ended=1 + 양측에 room_closed 이벤트.
function _closeOrderRoom(orderId, buyer, seller) {
    try {
        const roomId = _orderRoomId(orderId);
        _setOrderRoom(roomId, buyer, seller);
        db.run(`UPDATE chat_rooms SET ended = 1 WHERE roomId = ?`, [roomId], () => {});
        try { _emitToRoomUsers(roomId, 'room_closed', { roomId, orderId, buyer, seller }); } catch (_) {}
    } catch (_) {}
}

// 🦷 [기공소] 거래 성립 시(승인) 해당 상점이 기공소면 구매자 즐겨찾기에 자동 등록.
function _autoFavIfLab(buyer, productId) {
    try {
        db.get(`SELECT s.name AS sname, s.category AS cat FROM products p LEFT JOIN stores s ON p.storeId = s.id WHERE p.id = ?`, [productId], (e, row) => {
            if (!row || row.cat !== 'dental_lab' || !row.sname) return;
            db.get(`SELECT id FROM favorite_stores WHERE userName = ? AND targetStore = ?`, [buyer, row.sname], (e2, fav) => {
                if (!fav) db.run(`INSERT INTO favorite_stores (userName, targetStore) VALUES (?, ?)`, [buyer, row.sname], () => {});
            });
        });
    } catch (_) {}
}

// 💰 [에스크로] 주문 상품의 상점이 Admin 통합관리(admin_managed=1)인지 조회 → cb(managed:boolean, store)
function _orderStoreManaged(ord, cb) {
    db.get(`SELECT s.id AS sid, s.admin_managed AS am, s.name AS sname, s.category AS cat FROM products p LEFT JOIN stores s ON p.storeId = s.id WHERE p.id = ?`, [ord.productId], (e, row) => {
        cb(!!(row && Number(row.am) === 1), row || null);
    });
}

// 🚀 [v6] 판매자가 주문 승인 → 결제 처리 + status='approved'
//  · 일반 상점: 배민식 카드수령(잔액 이동 없이 매출기록만).
//  · 💰 Admin 통합관리 상점: 승인 시 구매자 잔액 → Admin(hi840508) 보관(에스크로). 구매확정 후 정산으로 상점에 지급.
app.post('/api/order/approve', (req, res) => {
    const seller = requireUser(req, res); if (!seller) return;   // ★신원=토큰
    const { orderId } = req.body;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 승인할 수 있습니다.' });
        if(ord.status === 'approved') return res.json({ success: true, message: '이미 승인됨', txId: ord.txId });   // 멱등
        if(ord.status !== 'pending') return res.status(400).json({ error: '이미 처리된 주문입니다.' });   // 취소/거절/확정/정산 등

        const amount = ord.amount || 0;
        const isCard = ord.pay_method === 'card';   // 💳 카드결제 주문(외부 카드 자금)
        db.get(`SELECT name FROM products WHERE id = ?`, [ord.productId], (e3, pRow) => {
            const pName = (pRow && pRow.name) || ord.productId;
            const date = new Date().toLocaleString('ko-KR');
            const payTag = isCard ? 'card' : 'balance';
            _orderStoreManaged(ord, (managed, info) => {
                const admin = _adminAccount();
                const isLab = !!(info && info.cat === 'dental_lab');
                // 🦷 기공소: 승인=금액확정만(결제 없음). status→awaiting_payment. 구매자가 결제해야 에스크로 보관 시작.
                if (isLab) {
                    if (amount <= 0) return res.status(400).json({ error: '금액이 확정되지 않았습니다. 먼저 확정 금액을 입력하고 승인하세요.' });
                    db.run(`UPDATE product_orders SET status='awaiting_payment' WHERE id=? AND status='pending'`, [orderId], function(fe){
                        if (fe) return res.status(500).json({ error: fe.message });
                        if (this.changes === 0) return res.status(400).json({ error: '이미 처리된 주문입니다.' });
                        _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'awaiting_payment', `✅ [승인] 판매자가 금액(${amount.toLocaleString()}원)을 확정·승인했습니다. 결제하시면 진행됩니다.`);
                        return res.json({ success: true, awaitingPayment: true, amount });
                    });
                    return;
                }
                // 🔒 [간편 의뢰서 0원 우회 차단] 에스크로(Admin 통합관리) 상점 주문은 금액 미확정(<=0)이면 승인 불가 → 재견적으로 금액 확정 후 승인.
                if (managed && amount <= 0) return res.status(400).json({ error: '금액이 확정되지 않은 의뢰서입니다. 먼저 금액을 확정(재견적)하세요.' });
                if (managed && amount > 0) {
                    // 💰 에스크로: 승인 시 자금이 Admin 보관으로 이동. pending→approved 원자적 플립으로 동시 승인 이중결제 차단.
                    db.serialize(() => {
                        db.run('BEGIN IMMEDIATE');
                        db.run(`UPDATE product_orders SET status = 'approved' WHERE id = ? AND status = 'pending'`, [orderId], function(fe) {
                            if (fe) { db.run('ROLLBACK'); return res.status(500).json({ error: fe.message }); }
                            if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 처리된 주문입니다.' }); }
                            const _afterHold = () => {
                                db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, pay_method, pg_approval) VALUES (?, ?, ?, ?, ?, 'original', ?, ?, ?, ?)`,
                                    [ord.buyer, ord.seller, ord.productId, pName, amount, new Date().toISOString(), date, payTag, ord.pg_approval || null],
                                    function(ie) {
                                        if (ie) { db.run('ROLLBACK'); return res.status(500).json({ error: ie.message }); }
                                        const txId = this.lastID;
                                        db.run(`UPDATE product_orders SET txId = ?, escrow_held = ? WHERE id = ?`, [txId, amount, orderId]);
                                        db.run('COMMIT', () => { _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'approved', `✅ [주문 승인] 결제(${amount.toLocaleString()}원)가 완료되어 주문이 확정되었습니다. 배송을 준비합니다.`); _autoFavIfLab(ord.buyer, ord.productId); res.json({ success: true, txId, amount, escrow: true, payMethod: payTag }); });
                                    });
                            };
                            if (isCard) {
                                // 💳 카드 에스크로: 외부 카드 자금 → Admin 보관(구매자 지갑 미차감).
                                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, admin], function(ue) {
                                    if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                                    _afterHold();
                                });
                            } else {
                                // 잔액 에스크로: 구매자 잔액 → Admin 보관(원자적 조건부 차감).
                                db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [amount, ord.buyer, amount], function(ue) {
                                    if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                                    if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '구매자 잔액이 부족하여 승인할 수 없습니다. (에스크로 결제)' }); }
                                    db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, admin]);
                                    _afterHold();
                                });
                            }
                        });
                    });
                } else {
                    // ★배민식 카드수령 모델★(일반 상점): 승인 = 주문확정 + 매출기록만. 구매자 잔액 이동 없음. pending→approved 원자적 플립.
                    db.serialize(() => {
                        db.run('BEGIN IMMEDIATE');
                        db.run(`UPDATE product_orders SET status = 'approved' WHERE id = ? AND status = 'pending'`, [orderId], function(fe) {
                            if (fe) { db.run('ROLLBACK'); return res.status(500).json({ error: fe.message }); }
                            if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 처리된 주문입니다.' }); }
                            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, pay_method, pg_approval) VALUES (?, ?, ?, ?, ?, 'original', ?, ?, ?, ?)`,
                                [ord.buyer, ord.seller, ord.productId, pName, amount, new Date().toISOString(), date, payTag, ord.pg_approval || null],
                                function(ie) {
                                    if (ie) { db.run('ROLLBACK'); return res.status(500).json({ error: ie.message }); }
                                    const txId = this.lastID;
                                    db.run(`UPDATE product_orders SET txId = ? WHERE id = ?`, [txId, orderId]);
                                    db.run('COMMIT', () => { _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'approved', '✅ [주문 승인] 주문이 확정되었습니다. 배송을 준비합니다.'); _autoFavIfLab(ord.buyer, ord.productId); res.json({ success: true, txId, amount, payMethod: payTag }); });
                                });
                        });
                    });
                }
            });
        });
    });
});

// 💳 구매자 결제 — 기공소가 금액확정·승인(awaiting_payment)한 주문을 구매자가 결제 → 에스크로 보관(→approved).
app.post('/api/order/pay', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // ★신원=토큰
    const { orderId } = req.body;
    const payMethod = (req.body.payMethod === 'card') ? 'card' : 'balance';
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if (err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (ord.buyer !== buyer) return res.status(403).json({ error: '본인 주문만 결제할 수 있습니다.' });
        if (ord.status === 'approved') return res.json({ success: true, message: '이미 결제됨', txId: ord.txId });   // 멱등
        if (ord.status !== 'awaiting_payment') return res.status(400).json({ error: '결제할 수 있는 상태가 아닙니다.' });
        const amount = ord.amount || 0;
        if (!(amount > 0)) return res.status(400).json({ error: '확정 금액이 없습니다.' });
        const admin = _adminAccount();
        const isCard = payMethod === 'card';
        db.get(`SELECT name FROM products WHERE id = ?`, [ord.productId], (e3, pRow) => {
            const pName = (pRow && pRow.name) || ord.productId;
            const date = new Date().toLocaleString('ko-KR');
            db.serialize(() => {
                db.run('BEGIN IMMEDIATE');
                db.run(`UPDATE product_orders SET status='approved', pay_method=? WHERE id=? AND status='awaiting_payment'`, [payMethod, orderId], function(fe){
                    if (fe) { db.run('ROLLBACK'); return res.status(500).json({ error: fe.message }); }
                    if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 처리된 주문입니다.' }); }
                    const makeKind = /^\[리메이크\]/.test(ord.memo || '') ? '리메이크' : (/^\[리페어\]/.test(ord.memo || '') ? '리페어' : '신규제작');
                    const _afterHold = () => {
                        db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, pay_method, pg_approval, make_kind) VALUES (?, ?, ?, ?, ?, 'original', ?, ?, ?, ?, ?)`,
                            [ord.buyer, ord.seller, ord.productId, pName, amount, new Date().toISOString(), date, payMethod, ord.pg_approval || null, makeKind],
                            function(ie){
                                if (ie) { db.run('ROLLBACK'); return res.status(500).json({ error: ie.message }); }
                                const txId = this.lastID;
                                db.run(`UPDATE product_orders SET txId=?, escrow_held=? WHERE id=?`, [txId, amount, orderId]);
                                db.run('COMMIT', () => { _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'approved', `💳 [결제 완료] 결제(${amount.toLocaleString()}원)가 완료되었습니다. 판매자가 상품을 준비합니다.`); _autoFavIfLab(ord.buyer, ord.productId); res.json({ success: true, txId, amount, escrow: true, payMethod }); });
                            });
                    };
                    if (isCard) {
                        db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, admin], function(ue){
                            if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                            _afterHold();
                        });
                    } else {
                        db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [amount, ord.buyer, amount], function(ue){
                            if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                            if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '잔액이 부족합니다. 충전 후 결제하세요.' }); }
                            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, admin]);
                            _afterHold();
                        });
                    }
                });
            });
        });
    });
});

// 🚀 [v6] 판매자가 주문 거절
app.post('/api/order/reject', (req, res) => {
    const seller = requireUser(req, res); if (!seller) return;   // ★신원=토큰
    const { orderId, reason } = req.body;
    db.get(`SELECT buyer, seller, status FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 거절할 수 있습니다.' });
        if(ord.status !== 'pending') return res.status(400).json({ error: '이미 처리된 주문입니다.' });
        db.run(`UPDATE product_orders SET status = 'rejected', memo = COALESCE(memo, '') || ? WHERE id = ? AND status = 'pending'`, ['\n[거절 사유] ' + (reason||''), orderId], () => {
            // ⏱ 거절 후 새 대화가 없으면 24시간 뒤 대화방 자동 삭제(모든 참여자). 거절 안내 메시지 이후 id 기준.
            const roomId = _orderRoomId(orderId);
            _setOrderRoom(roomId, ord.buyer, ord.seller);
            const date = new Date().toLocaleString('ko-KR');
            const msg = '❌ [주문 거절] 판매자가 주문을 거절했습니다.' + (reason ? (' 사유: ' + reason) : '') + '\n※ 새로운 대화가 없으면 24시간 후 이 대화방은 자동으로 사라집니다.';
            db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?, '__system__', NULL, ?, ?, ?)`, [roomId, msg, date, new Date().toISOString()], function() {
                const mid = this.lastID;
                try { _emitToRoomUsers(roomId, 'receive_message', { roomId, sender: '__system__', message: msg, id: mid, date }); } catch (_) {}
                try { _emitToRoomUsers(roomId, 'order_status', { orderId, status: 'rejected', buyer: ord.buyer, seller: ord.seller }); } catch (_) {}
                const expireAt = Date.now() + 24 * 60 * 60 * 1000;
                db.run(`UPDATE chat_rooms SET expire_at = ?, expire_after_id = ? WHERE roomId = ?`, [expireAt, mid, roomId], () => {});
                res.json({ success: true });
            });
        });
    });
});

// ⏱ 거절 대화방 자동 삭제 스윕: expire_at 경과 & 그 이후 새 대화 없으면 방+대화 삭제(모든 참여자에서 사라짐). 새 대화가 있으면 예약 취소.
function _rejectRoomSweep() {
    try {
        const now = Date.now();
        db.all(`SELECT roomId, expire_after_id, buyer, seller FROM chat_rooms WHERE expire_at IS NOT NULL AND expire_at <= ?`, [now], (e, rows) => {
            if (e || !rows || !rows.length) return;
            rows.forEach(r => {
                db.get(`SELECT MAX(id) AS mx FROM chats WHERE roomId = ?`, [r.roomId], (e2, row2) => {
                    const mx = (row2 && row2.mx) || 0;
                    if (mx > (r.expire_after_id || 0)) {
                        db.run(`UPDATE chat_rooms SET expire_at = NULL, expire_after_id = NULL WHERE roomId = ?`, [r.roomId], () => {});   // 새 대화 → 취소
                    } else {
                        db.run(`DELETE FROM chats WHERE roomId = ?`, [r.roomId], () => {});
                        db.run(`DELETE FROM chat_rooms WHERE roomId = ?`, [r.roomId], () => {});
                        try { _emitToRoomUsers(r.roomId, 'room_closed', { roomId: r.roomId, buyer: r.buyer, seller: r.seller }); } catch (_) {}
                    }
                });
            });
        });
    } catch (_) {}
}
setTimeout(_rejectRoomSweep, 40 * 1000);
setInterval(_rejectRoomSweep, 30 * 60 * 1000);

// ⏱ 고객센터(이재준) 대화방의 24시간 지난 대화 자동 삭제
function _customerCenterSweep() {
    try {
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        db.run(`DELETE FROM chats WHERE roomId LIKE 'room_msg_%' AND roomId LIKE '%이재준%' AND created_at IS NOT NULL AND created_at < ?`, [cutoff], function() {
            if (this && this.changes) console.log('[고객센터] 24시간 경과 대화 ' + this.changes + '건 자동삭제');
        });
    } catch (_) {}
}
setTimeout(_customerCenterSweep, 50 * 1000);
setInterval(_customerCenterSweep, 60 * 60 * 1000);

// 🚀 [v6] 구매자가 자신의 pending 주문 취소
app.post('/api/order/cancel', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // ★신원=토큰
    const { orderId } = req.body;
    db.get(`SELECT buyer, status FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.buyer !== buyer) return res.status(403).json({ error: '본인 주문만 취소 가능' });
        if(ord.status !== 'pending') return res.status(400).json({ error: 'pending 상태만 취소 가능' });
        db.run(`UPDATE product_orders SET status = 'cancelled' WHERE id = ?`, [orderId], () => res.json({ success: true }));
    });
});

// 💰 [간편 의뢰서 재견적/금액 확정] 판매자(기공소)가 대기(pending) 주문의 금액을 확정. 에스크로 0원 우회 방지 — 승인 전 필수.
app.post('/api/order/requote', (req, res) => {
    const seller = requireUser(req, res); if (!seller) return;   // ★신원=토큰
    const { orderId } = req.body;
    const amount = Math.floor(Number(req.body.amount) || 0);
    if (!(amount > 0)) return res.status(400).json({ error: '재견적 금액을 확인하세요. (1원 이상)' });
    db.get(`SELECT buyer, seller, status, bundle_html FROM product_orders WHERE id = ?`, [orderId], (e, ord) => {
        if (e || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 재견적할 수 있습니다.' });
        if (ord.status !== 'pending') return res.status(400).json({ error: '대기(pending) 주문만 재견적할 수 있습니다.' });
        // 🧾 기공 의뢰서의 '금액 미정'을 최종 확정 금액으로 갱신(마지막 금액 미정 항목 = 이번 사이클/리메이크 #2).
        let nb = ord.bundle_html || '';
        const finalDiv = `<div class="amt" style="color:#2563eb;">최종 확정 금액: ${amount.toLocaleString()}원</div>`;
        const amtRe = /<div class="amt"[^>]*>[^<]*금액 미정[^<]*<\/div>/;
        if (amtRe.test(nb)) nb = nb.replace(amtRe, finalDiv);
        else if (nb.includes('</body>')) nb = nb.replace('</body>', finalDiv + '</body>');
        else nb += finalDiv;
        db.run(`UPDATE product_orders SET amount = ?, bundle_html = ? WHERE id = ? AND status = 'pending'`, [amount, nb, orderId], function(ue) {
            if (ue) return res.status(500).json({ error: ue.message });
            if (this.changes === 0) return res.status(400).json({ error: '이미 처리된 주문입니다.' });
            _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'pending', `💰 [금액 확정] 의뢰 금액이 ${amount.toLocaleString()}원으로 확정되었습니다. 승인 시 결제됩니다.`);
            res.json({ success: true, orderId, amount });
        });
    });
});

// 🚚 판매자: 주문 상태 변경 (배송 등록/배송 완료/환불 수락). 배송 등록은 선택(송장 없이도 배송중 가능).
//  status: 'shipping'(배송중) | 'delivered'(배송완료) | 'refunded'(환불수락)
app.post('/api/order/status', (req, res) => {
    const seller = requireUser(req, res); if (!seller) return;   // ★신원=토큰
    const { orderId, status, tracking } = req.body || {};
    const allowed = ['shipping', 'delivered', 'refunded'];
    if (!allowed.includes(status)) return res.status(400).json({ error: '허용되지 않은 상태' });
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if (err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (ord.seller !== seller) return res.status(403).json({ error: '본인 판매 주문만 변경 가능' });
        if (status === 'refunded') {
            // ★환불 수락★: 매출 취소 표시 + (에스크로 상점이면) Admin 보관금액을 구매자에게 반환. 중복환불·미결제환불·정산완료 차단.
            if (ord.status === 'refunded') return res.status(400).json({ error: '이미 환불 처리된 주문입니다.' });
            if (ord.settled) return res.status(400).json({ error: '이미 정산 완료된 주문은 환불할 수 없습니다.' });
            if (ord.status === 'confirmed') return res.status(400).json({ error: '구매확정된 주문은 환불할 수 없습니다.' });
            if (!['approved', 'shipping', 'delivered', 'refund_requested'].includes(ord.status)) return res.status(400).json({ error: '배송 완료 전(구매확정 전) 주문만 환불할 수 있습니다.' });
            const hold = ord.escrow_held || 0;
            const isCard = ord.pay_method === 'card';   // 💳 카드결제 주문 → PG 취소(카드사로 환불), 구매자 지갑 미입금
            const _refundMsg = hold > 0
                ? (isCard ? `↩️ [환불 완료] 카드 결제(${hold.toLocaleString()}원)가 취소되어 카드사로 환불됩니다.` : `↩️ [환불 완료] 결제금액(${hold.toLocaleString()}원)이 구매자에게 환불되었습니다.`)
                : '↩️ [환불 처리] 주문이 환불 처리되었습니다.';
            const _finish = () => db.run(`UPDATE product_orders SET status = 'refunded', escrow_held = 0 WHERE id = ?`, [orderId], () => { _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'refunded', _refundMsg + ' 이 대화방은 종료됩니다.'); _closeOrderRoom(orderId, ord.buyer, ord.seller); res.json({ success: true, refundedToBuyer: (hold > 0 && !isCard) ? hold : 0, refundedToCard: (hold > 0 && isCard) ? hold : 0 }); });
            const _markTx = () => {
                if (ord.txId) {
                    db.get(`SELECT * FROM transactions WHERE id = ?`, [ord.txId], (e3, otx) => {
                        db.run(`UPDATE transactions SET refunded = 1 WHERE id = ?`, [ord.txId]);   // 매출 취소(구매내역·정산에서 제외)
                        if (otx) {
                            const now = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
                            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, refunded) VALUES (?, ?, ?, ?, ?, 'refund', ?, ?, 1)`,
                                [otx.seller, otx.buyer, otx.productId, `[매출취소] ${otx.productName || ''}`, otx.amount, rawDate, now], () => _finish());
                        } else { _finish(); }
                    });
                } else { _finish(); }
            };
            if (hold > 0) {
                // 💰 에스크로 반환: Admin 보관금액 차감(원자적). 잔액결제면 구매자 지갑 환불, 카드결제면 PG 취소(구매자 지갑 미입금).
                const admin = _adminAccount();
                db.serialize(() => {
                    db.run('BEGIN IMMEDIATE');
                    db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [hold, admin, hold], function(ue) {
                        if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                        if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: 'Admin 보관 잔액이 부족하여 환불할 수 없습니다.' }); }
                        if (!isCard) db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [hold, ord.buyer]);   // 카드는 외부 환불
                        db.run('COMMIT', () => _markTx());
                    });
                });
            } else { _markTx(); }
        } else {
            // 배송완료 시각 기록(자동확정 3일 기준). 배송중/완료 상태 변경.
            const dlvAt = (status === 'delivered') ? (ord.delivered_at || new Date().toISOString()) : ord.delivered_at;
            const _trk = tracking || ord.tracking || null;
            db.run(`UPDATE product_orders SET status = ?, tracking = ?, courier = ?, delivered_at = ? WHERE id = ?`, [status, _trk, req.body.courier || ord.courier || null, dlvAt || null, orderId], () => {
                const msg = status === 'delivered' ? '📦 [배송 완료] 상품이 배송 완료되었습니다. 구매확정을 눌러주세요. (배송완료 3일 후 자동 구매확정)'
                          : (_trk ? `🚚 [배송 시작] 송장번호 ${_trk} 로 배송이 시작되었습니다.` : '🚚 [배송 시작] 배송이 시작되었습니다.');
                _notifyOrderStatus(ord.buyer, ord.seller, orderId, status, msg);
                res.json({ success: true });
            });
        }
    });
});

// 💰 [에스크로] 구매자: 구매확정 → 정산대기(confirmed). 자금은 Admin이 계속 보관, 이후 Admin의 정산 버튼으로 상점에 지급.
//  배송완료(delivered) 또는 배송중(shipping) 주문을 구매자가 확정. (지급 이체는 여기서 하지 않음 — 정산 시 처리)
app.post('/api/order/confirm', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;
    const { orderId } = req.body;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if (err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (ord.buyer !== buyer) return res.status(403).json({ error: '본인 주문만 확정할 수 있습니다.' });
        if (ord.status === 'confirmed') return res.json({ success: true, message: '이미 구매확정됨' });
        if (!['delivered', 'shipping', 'approved'].includes(ord.status)) return res.status(400).json({ error: '배송/승인 상태의 주문만 구매확정할 수 있습니다.' });
        const now = new Date();
        const month = _kstMonth();   // YYYY-MM (정산 귀속월, KST 기준)
        db.run(`UPDATE product_orders SET status = 'confirmed', confirmed_at = ?, settle_month = ? WHERE id = ?`, [now.toISOString(), month, orderId], () => { _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'confirmed', '🎉 [구매 확정] 구매가 확정되었습니다. (정산 대기) 이 대화방은 종료됩니다.'); _closeOrderRoom(orderId, ord.buyer, ord.seller); res.json({ success: true }); });
    });
});

// 🔁 [리메이크/리페어] 구매자가 배송 단계 주문에 대해 재제작/수리를 요청 → 원주문 복제한 새 pending 주문 생성.
//   이후 흐름은 처음 구매와 동일: 기공소 금액확정·승인(awaiting_payment) → 구매자 결제 → 배송 → 구매확정 → 정산(수수료 동일).
app.post('/api/order/remake', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;
    const kind = req.body.kind === 'repair' ? 'repair' : 'remake';
    const label = kind === 'repair' ? '리페어' : '리메이크';
    const reason = (req.body.reason || '').toString().slice(0, 500);
    const orderId = req.body.orderId;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if (err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (ord.buyer !== buyer) return res.status(403).json({ error: '본인 주문만 요청할 수 있습니다.' });
        if (!['shipping', 'delivered'].includes(ord.status)) return res.status(400).json({ error: '배송(제작완료·배송중/배송완료) 단계 주문만 리메이크/리페어를 요청할 수 있습니다.' });
        const date = new Date().toLocaleString('ko-KR');
        // 1) 원 사이클(현재 배송분) 구매확정 처리 → 정산 대상. 단, 대화방은 유지(리메이크 진행).
        const nowISO = new Date().toISOString();
        db.run(`UPDATE product_orders SET status='confirmed', confirmed_at=?, settle_month=? WHERE id=? AND status IN ('shipping','delivered')`, [nowISO, _kstMonth(), orderId], function() {
            // 2) 같은 기공 의뢰서에 '기공물 정보 #2 (리메이크/리페어)'를 추가한 새 주문 생성(처음 구매와 동일 흐름).
            const sec2 = `<h2>기공물 정보 #2 · ${label}</h2>`
                + `<div class="grid"><div><b>구분</b> ${label}</div><div><b>원주문</b> #${orderId}</div></div>`
                + (reason ? `<div class="sec">요청사항: ${String(reason).replace(/</g, '&lt;')}</div>` : '')
                + `<div class="amt" style="color:#b45309;">금액 미정 (기공소 확정 예정)</div>`;
            let nb = ord.bundle_html || '';
            if (nb.includes('</body>')) nb = nb.replace('</body>', sec2 + '</body>'); else nb += sec2;
            const newMemo = `[${label}] 원주문 #${orderId}` + (reason ? (' · ' + reason) : '');
            db.run(`INSERT INTO product_orders (productId, buyer, seller, bundle_html, memo, form_data, pdf_filled_data, buyer_info, status, amount, created_at, pay_method, remake_of) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, 'balance', ?)`,
                [ord.productId, ord.buyer, ord.seller, nb, newMemo, ord.form_data || '{}', '', ord.buyer_info || '{}', date, orderId],
                function(ie) {
                    if (ie) return res.status(500).json({ error: ie.message });
                    const newId = this.lastID;
                    db.get(`SELECT p.name AS pname, s.id AS sid, s.name AS sname FROM products p LEFT JOIN stores s ON p.storeId = s.id WHERE p.id = ?`, [ord.productId], (e2, row) => {
                        _notifyOrderStatus(ord.buyer, ord.seller, newId, 'pending', `🔁 [${label} 요청] 구매자가 ${label}를 요청했습니다. 판매자가 금액을 확정·승인하면 결제 후 진행됩니다.`);
                        res.json({ success: true, orderId: newId, label, seller: ord.seller, storeId: (row && row.sid) || '', storeName: (row && row.sname) || '', productName: (row && row.pname) || label });
                    });
                });
        });
    });
});

// 💰 [에스크로] 구매자: 환불 요청 → status='refund_requested'. 상점 주인이 /api/order/status(refunded)로 승인하면 Admin 보관금 → 구매자 반환.
app.post('/api/order/refund-request', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;
    const { orderId, reason } = req.body;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if (err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (ord.buyer !== buyer) return res.status(403).json({ error: '본인 주문만 환불 요청할 수 있습니다.' });
        if (ord.settled) return res.status(400).json({ error: '정산 완료된 주문은 환불 요청할 수 없습니다.' });
        if (ord.status === 'confirmed') return res.status(400).json({ error: '구매확정된 주문은 환불 요청할 수 없습니다.' });
        if (!['approved', 'shipping', 'delivered'].includes(ord.status)) return res.status(400).json({ error: '배송 완료 전(구매확정 전) 주문만 환불 요청할 수 있습니다.' });
        db.run(`UPDATE product_orders SET status = 'refund_requested', memo = COALESCE(memo,'') || ? WHERE id = ?`, ['\n[환불요청] ' + (reason || ''), orderId], () => { _notifyOrderStatus(ord.buyer, ord.seller, orderId, 'refund_requested', '↩️ [환불 요청] 구매자가 환불을 요청했습니다. 판매자 승인 시 환불됩니다.' + (reason ? ' 사유: ' + reason : '')); res.json({ success: true }); });
    });
});

// 💰 [에스크로] 3일 자동 구매확정 스윕: 배송완료(delivered) 후 3일 지난 에스크로 주문을 자동 confirmed 처리(구매자 미확정 시).
//  자금 이동 없음(정산 대기로 전환만). 1시간마다 실행 + 부팅 30초 후 1회.
function _autoConfirmSweep() {
    try {
        const cutoff = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
        db.all(`SELECT id, buyer, seller, delivered_at FROM product_orders WHERE status='delivered' AND escrow_held > 0 AND settled = 0 AND delivered_at IS NOT NULL AND delivered_at <= ?`, [cutoff], (e, rows) => {
            if (e || !rows || !rows.length) return;
            const now = new Date(); const month = _kstMonth();   // 정산 귀속월(KST 기준)
            rows.forEach(r => db.run(`UPDATE product_orders SET status='confirmed', confirmed_at = ?, settle_month = ? WHERE id = ?`, [now.toISOString(), month, r.id], () => { _notifyOrderStatus(r.buyer, r.seller, r.id, 'confirmed', '🎉 [자동 구매확정] 배송완료 3일 경과로 구매가 자동 확정되었습니다. (정산 대기) 이 대화방은 종료됩니다.'); _closeOrderRoom(r.id, r.buyer, r.seller); }));
            console.log(`[에스크로] 자동 구매확정 ${rows.length}건 (배송완료 3일 경과)`);
        });
    } catch (_) {}
}
setTimeout(_autoConfirmSweep, 30 * 1000);
setInterval(_autoConfirmSweep, 60 * 60 * 1000);

// 🚀 [v6] 단일 주문 조회 (orderId 기준; 채팅 카드 클릭 시 사용)
app.get('/api/order/:orderId', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [req.params.orderId], (err, row) => {
        if(err || !row) return res.status(404).json({ error: '주문 없음' });
        if (me !== row.buyer && me !== row.seller && !isAdminName(me)) return res.status(403).json({ error: '본인 주문만 조회할 수 있습니다.' });   // 🔐 당사자/관리자만
        // 🦷 리메이크/리페어 노출 판단용 상점 카테고리 포함
        db.get(`SELECT s.category AS cat FROM products p LEFT JOIN stores s ON p.storeId = s.id WHERE p.id = ?`, [row.productId], (e2, sr) => {
            row.storeCategory = (sr && sr.cat) || null;
            res.json(row);
        });
    });
});

app.get('/api/product/orders/:seller', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.seller)) return;   // 🔐 본인 판매 주문만
    db.all(`SELECT * FROM product_orders WHERE seller = ? ORDER BY id DESC LIMIT 100`, [req.params.seller], (err, rows) => res.json(rows || []));
});

// 🚀 [v7p+] 판매자에게 대기 중인 주문 개수 (5초마다 폴링) + 구매자에게 본인 pending 개수
app.get('/api/orders/pending/:userName', (req, res) => {
    const name = req.params.userName;
    db.all(
        `SELECT id, productId, buyer, seller, amount, memo, created_at,
                (SELECT name FROM products WHERE id = product_orders.productId) as productName
         FROM product_orders WHERE status = 'pending' AND (seller = ? OR buyer = ?) ORDER BY id DESC LIMIT 50`,
        [name, name],
        (err, rows) => {
            if(err) return res.status(500).json({ error: err.message });
            const list = rows || [];
            const asSeller = list.filter(o => o.seller === name);
            const asBuyer = list.filter(o => o.buyer === name);
            res.json({
                sellerPending: asSeller.length, sellerPendingOrders: asSeller,
                buyerPending: asBuyer.length, buyerPendingOrders: asBuyer
            });
        }
    );
});

// 🚀 [v7p4] 자신의 pending 주문 일괄 정리 (사용자가 수동으로 호출 — "내 화면의 알림 모두 끄기")
app.post('/api/orders/dismiss-all', (req, res) => {
    const userName = requireUser(req, res); if (!userName) return;   // 🔐 신원=토큰(본문 userName 무시)
    // 본인이 판매자인 pending 주문을 dismissed 상태로 변경 (실제 거절은 아니지만 알림에서 제외)
    db.run(
        `UPDATE product_orders SET status = 'dismissed' WHERE seller = ? AND status = 'pending'`,
        [userName],
        function(err) {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ success: true, dismissed: this.changes });
        }
    );
});

// 🚀 [v7p4] 판매자가 자신에게 온 모든 주문 보기 (대기/승인/거절/취소 포함, 거래 상태 확인용)
app.get('/api/orders/seller/:seller', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.seller)) return;   // 🔐 본인 판매 주문 목록만
    const seller = req.params.seller;
    db.all(
        `SELECT po.*,
                (SELECT name FROM products WHERE id = po.productId) as productName
         FROM product_orders po WHERE seller = ? ORDER BY id DESC LIMIT 200`,
        [seller],
        (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json(rows || [])
    );
});

// 🚀 [v7p3] 상품 리뷰 등록 (구매 완료 시)
app.post('/api/review/submit', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // 🔐 신원=토큰(본문 buyer 무시)
    const { productId, seller, rating, review_text, skipped } = req.body;
    if(!productId) return res.status(400).json({ error: 'productId 필수' });
    const r = Math.max(1, Math.min(5, Number(rating) || 3));
    const now = new Date().toISOString();
    // 같은 구매자가 같은 상품에 이미 리뷰 작성했는지 확인 — 중복 허용 X
    db.get(`SELECT id FROM product_reviews WHERE productId = ? AND buyer = ?`, [productId, buyer], (gerr, existing) => {
        if(existing) {
            // 업데이트
            db.run(`UPDATE product_reviews SET rating = ?, review_text = ?, skipped = ?, created_at = ? WHERE id = ?`,
                [r, review_text || '', skipped ? 1 : 0, now, existing.id],
                (uerr) => uerr ? res.status(500).json({ error: uerr.message }) : res.json({ ok: true, updated: true })
            );
        } else {
            db.run(`INSERT INTO product_reviews (productId, buyer, seller, rating, review_text, skipped, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [productId, buyer, seller || null, r, review_text || '', skipped ? 1 : 0, now],
                function(ierr) { ierr ? res.status(500).json({ error: ierr.message }) : res.json({ ok: true, id: this.lastID }); }
            );
        }
    });
});

// 🚀 [v7p3] 상품의 리뷰 목록 + 평균 별점 조회
app.get('/api/reviews/:productId', (req, res) => {
    const pid = req.params.productId;
    db.all(`SELECT * FROM product_reviews WHERE productId = ? ORDER BY id DESC LIMIT 100`, [pid], (err, rows) => {
        if(err) return res.status(500).json({ error: err.message });
        const list = rows || [];
        const total = list.length;
        const sum = list.reduce((s, r) => s + (Number(r.rating) || 0), 0);
        const avg = total > 0 ? (sum / total).toFixed(2) : null;
        res.json({ reviews: list, total, average: avg ? Number(avg) : null });
    });
});

// 🚀 [v7p3] 여러 상품의 평점 일괄 조회 (마켓 그리드용)
app.post('/api/reviews/summary', (req, res) => {
    const ids = req.body.productIds || [];
    if(!Array.isArray(ids) || ids.length === 0) return res.json({});
    const placeholders = ids.map(() => '?').join(',');
    db.all(
        `SELECT productId, AVG(rating) as avg_rating, COUNT(*) as count FROM product_reviews WHERE productId IN (${placeholders}) GROUP BY productId`,
        ids,
        (err, rows) => {
            if(err) return res.status(500).json({ error: err.message });
            const m = {};
            (rows || []).forEach(r => { m[r.productId] = { average: Number(Number(r.avg_rating).toFixed(2)), count: r.count }; });
            res.json(m);
        }
    );
});

// 🚀 [v6] 채팅방 메타 upsert (주문 채팅방 생성/업데이트)
app.post('/api/chat-room/upsert', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // 🔐 로그인 필수
    const { roomId, type, buyer, seller, storeId, storeName, lastProductId, lastProductName } = req.body;
    const now = new Date().toISOString();
    db.get(`SELECT id, buyer, seller FROM chat_rooms WHERE roomId = ?`, [roomId], (err, row) => {
        if(row) {
            // 🔐 기존 방: 저장된 참가자(buyer/seller)만 수정 가능(참가자 하이재킹 차단). 참가자 필드는 갱신하지 않음.
            if (me !== row.buyer && me !== row.seller && !isAdminName(me)) return res.status(403).json({ error: '본인이 참여한 대화방만 수정할 수 있습니다.' });
            _setOrderRoom(roomId, row.buyer, row.seller);
            db.run(`UPDATE chat_rooms SET storeName = COALESCE(?, storeName), lastProductId = ?, lastProductName = ?, updated_at = ?, ended = 0 WHERE roomId = ?`,
                [storeName, lastProductId || null, lastProductName || null, now, roomId],
                () => res.json({ success: true, updated: true }));
        } else {
            // 🔐 신규 방: 생성자는 반드시 참가자(buyer 또는 seller) 중 하나여야 함.
            if (me !== buyer && me !== seller && !isAdminName(me)) return res.status(403).json({ error: '본인이 참여한 대화방만 생성할 수 있습니다.' });
            _setOrderRoom(roomId, buyer, seller);   // 💬 주문방 참가자 캐시(소켓 전송용)
            db.run(`INSERT INTO chat_rooms (roomId, type, buyer, seller, storeId, storeName, lastProductId, lastProductName, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [roomId, type || 'order', buyer, seller, storeId || null, storeName || null, lastProductId || null, lastProductName || null, now, now],
                () => res.json({ success: true, created: true }));
        }
    });
});

// 🚀 [v6] 사용자의 채팅방 메타 일괄 조회 (양측 동기화 정보)
app.get('/api/chat-rooms/:user', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.user)) return;   // 🔐 본인 대화방 메타만
    const user = req.params.user;
    db.all(`SELECT * FROM chat_rooms WHERE (buyer = ? OR seller = ?) AND ended = 0 ORDER BY updated_at DESC`, [user, user], (err, rows) => {
        res.json(rows || []);
    });
});

// 🚀 [v6] 채팅방 나가기 — order 타입은 양측 동시 종료
app.post('/api/chat-room/leave', (req, res) => {
    const user = requireUser(req, res); if (!user) return;   // 🔐 신원=토큰(본문 user 무시)
    const { roomId } = req.body;
    db.get(`SELECT * FROM chat_rooms WHERE roomId = ?`, [roomId], (err, row) => {
        if(!row) {
            // 메타 없는 일반 친구 채팅 — 그냥 friends 삭제
            return res.json({ success: true, deleted: 'friend-only' });
        }
        // 🔐 참가자(또는 관리자)만 나가기 가능 — 타인이 주문방을 강제 종료하는 것 차단.
        if (user !== row.buyer && user !== row.seller && !isAdminName(user)) return res.status(403).json({ error: '참여한 대화방만 나갈 수 있습니다.' });
        if(row.type === 'order') {
            // 주문 대화방: 한쪽이 나가면 양측 종료
            db.serialize(() => {
                db.run(`UPDATE chat_rooms SET ended = 1, updated_at = ? WHERE roomId = ?`, [new Date().toISOString(), roomId]);
                // 양측 friends에서 서로 제거
                db.run(`DELETE FROM friends WHERE (userName = ? AND friendName = ?) OR (userName = ? AND friendName = ?)`,
                    [row.buyer, row.seller, row.seller, row.buyer], () => {
                    res.json({ success: true, type: 'order', endedBothSides: true });
                });
            });
        } else {
            // 일반 친구 채팅: 본인 쪽만 friends 삭제
            const other = row.buyer === user ? row.seller : row.buyer;
            db.run(`DELETE FROM friends WHERE userName = ? AND friendName = ?`, [user, other], () => {
                res.json({ success: true, type: 'normal' });
            });
        }
    });
});

// 🚀 [v6] 통합 사용자/상점 검색 (ID/실명/전화번호/브랜드명)
app.get('/api/search/users-and-stores', (req, res) => {
    const q = (req.query.q || '').toLowerCase().trim();
    if(!q) return res.json({ users: [], stores: [] });
    const like = `%${q}%`;
    db.all(`SELECT name, realname, profilePic FROM users WHERE LOWER(name) LIKE ? OR LOWER(realname) LIKE ? OR phone LIKE ? LIMIT 20`, [like, like, like], (err, users) => {
        db.all(`SELECT id, name, owner, logo, category, description FROM stores WHERE status = 'active' AND LOWER(name) LIKE ? LIMIT 20`, [like], (err2, stores) => {
            res.json({ users: users || [], stores: stores || [] });
        });
    });
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/products/active', (req, res) => { db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' AND p.storeId NOT LIKE 'room_msg_%' ORDER BY p.id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT p.*, s.category AS storeCategory, IFNULL(s.admin_managed,0) AS storeManaged FROM products p LEFT JOIN stores s ON p.storeId = s.id WHERE p.id = ?`, [req.params.id], (err, row) => res.json(row || {})); });
app.post('/api/product/edit', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰
    const b = req.body || {};
    db.get(`SELECT seller FROM products WHERE id = ?`, [b.id], (e, prod) => {
        if (e || !prod) return res.status(404).json({ error: '상품을 찾을 수 없습니다.' });
        if (prod.seller !== me && !isAdminName(me)) return res.status(403).json({ error: '본인 상품만 수정할 수 있습니다.' });
        // 제공된 필드만 갱신(COALESCE) — 썸네일만 바꿀 때 이름/설명이 지워지지 않도록.
        db.run(`UPDATE products SET name = COALESCE(?, name), description = COALESCE(?, description), stream_time = COALESCE(?, stream_time), stream_unit = COALESCE(?, stream_unit), price_stream = COALESCE(?, price_stream), price_original = COALESCE(?, price_original), thumbnail = COALESCE(?, thumbnail) WHERE id = ?`,
            [ b.name != null ? b.name : null, b.description != null ? b.description : null,
              b.stream_time != null ? (Number(b.stream_time)||0) : null, b.stream_unit != null ? b.stream_unit : null,
              b.price_stream != null ? (Number(b.price_stream)||0) : null, b.price_original != null ? (Number(b.price_original)||0) : null,
              b.thumbnail != null ? b.thumbnail : null, b.id ],
            () => res.json({ success: true }));
    });
});

app.post('/api/admin/product/delete', (req, res) => { 
    if(!requireAdmin(req,res)) return;
    db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); 
});
// 🚀 [v8+] Admin이 임의 상점을 강제 폐쇄 (소유자 무관)
app.post('/api/admin/store/delete', (req, res) => {
    if(!requireAdmin(req,res)) return;
    db.serialize(() => {
        db.run(`DELETE FROM products WHERE storeId = ?`, [req.body.id]);
        db.run(`DELETE FROM stores WHERE id = ?`, [req.body.id], () => res.json({ success: true }));
    });
});
app.post('/api/product/delete', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰
    db.get(`SELECT seller FROM products WHERE id = ?`, [req.body.id], (e, prod) => {
        if (e || !prod) return res.status(404).json({ error: '상품을 찾을 수 없습니다.' });
        if (prod.seller !== me && !isAdminName(me)) return res.status(403).json({ error: '본인 상품만 삭제할 수 있습니다.' });
        db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true }));
    });
});

app.post('/api/buy', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // ★신원=토큰
    let amount = Number(req.body.amount) || 0; const pType = req.body.purchaseType; const rawDate = new Date().toISOString();
    const seller = req.body.seller;
    const payMethod = req.body.payMethod === 'card' ? 'card' : 'balance';   // 💳 결제수단(구매자 선택)
    if (!seller) return res.status(400).json({ error: '판매자 정보가 없습니다.' });
    // 🔒 금액 서버검증: 일반 상품은 서버 상품가로 강제(클라이언트 1원 결제 방지). rx 의뢰서는 재견적 금액 유지. 미등록 productId면 전송값 사용.
    db.get(`SELECT rx_form, price_original, price_stream FROM products WHERE id = ?`, [req.body.productId], (pe, prod) => {
        if (pe) return res.status(500).json({ error: pe.message });
        if (prod && !prod.rx_form) {
            amount = (pType === 'stream') ? (Number(prod.price_stream) || Number(prod.price_original) || 0)
                                          : (Number(prod.price_original) || Number(prod.price_stream) || 0);
        }
        if (amount <= 0) return res.status(400).json({ error: '결제 금액이 올바르지 않습니다.' });
    db.get(`SELECT name FROM users WHERE name = ?`, [seller], (se, sRow) => {
        if (se) return res.status(500).json({ error: se.message });
        if (!sRow) return res.status(404).json({ error: '판매자를 찾을 수 없습니다.' });
        const dateStr = new Date().toLocaleString('ko-KR');
        const _insertTx = (pgApproval) => {
            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, pay_method, pg_approval) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [buyer, seller, req.body.productId, req.body.productName, amount, pType, rawDate, dateStr, payMethod, pgApproval || null],
                () => res.json({ success: true, payMethod, approvalNo: pgApproval || null }));
        };
        if (payMethod === 'card') {
            // 💳 카드결제: 외부 카드 자금 → 판매자 입금(구매자 지갑 미차감). PG 승인 실패 시 400.
            const auth = _pgAuthorize({ payer: buyer, amount, method: 'card', cardPw: req.body.cardPw });
            if (!auth.ok) return res.status(400).json({ error: '카드 승인 실패: ' + (auth.error || '') });
            db.serialize(() => {
                db.run('BEGIN IMMEDIATE');
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller], function(ue) {
                    if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                    db.run('COMMIT', () => _insertTx(auth.approvalNo));
                });
            });
        } else {
            // 잔액결제: 원자적 조건부 차감(BEGIN IMMEDIATE + balance>=? + this.changes)
            db.serialize(() => {
                db.run('BEGIN IMMEDIATE');
                db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [amount, buyer, amount], function(ue) {
                    if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                    if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '잔액 부족' }); }
                    db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
                    db.run('COMMIT', () => _insertTx(null));
                });
            });
        }
    });
    });
});

// 🚀 장바구니 일괄 결제 — 한 번에 결제하되 거래내역에는 개별 상품 단위로 기록 (환불 가능)
app.post('/api/buy/cart', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // ★신원=토큰
    const { items } = req.body; // items: [{productId, productName, seller, amount, purchaseType}]
    if(!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "장바구니가 비어있습니다." });
    const payMethod = req.body.payMethod === 'card' ? 'card' : 'balance';   // 💳 결제수단
    // 판매자 정보 필수
    for (const it of items) {
        if (!it.seller) return res.status(400).json({ error: '판매자 정보가 없는 상품이 있습니다.' });
    }
    // 🔒 금액 서버검증: 상품가를 서버에서 조회해 일반 상품 금액을 서버가로 덮어씀(1원 결제 방지). rx 의뢰서/미등록 productId는 전송값 유지.
    const _pids = [...new Set(items.map(i => i.productId).filter(Boolean))];
    const _afterPrice = () => {
        for (const it of items) {
            if ((Number(it.amount) || 0) <= 0) return res.status(400).json({ error: '결제 금액이 올바르지 않은 상품이 있습니다.' });
        }
        const total = items.reduce((s, i) => s + (Number(i.amount) || 0), 0);
        // 같은 판매자에게 가는 금액들을 합산해서 한 번에 잔액 처리
        const sellerSums = {};
        items.forEach(i => { sellerSums[i.seller] = (sellerSums[i.seller] || 0) + Number(i.amount); });
        const sellers = Object.keys(sellerSums);
        // 판매자 존재 검증
        db.all(`SELECT name FROM users WHERE name IN (${sellers.map(() => '?').join(',')})`, sellers, (se, srows) => {
        if (se) return res.status(500).json({ error: se.message });
        const found = new Set((srows || []).map(r => r.name));
        if (sellers.some(s => !found.has(s))) return res.status(404).json({ error: '존재하지 않는 판매자가 포함되어 있습니다.' });
        const now = new Date(); const dateStr = now.toLocaleString('ko-KR');
        let pgApproval = null;
        if (payMethod === 'card') {
            const auth = _pgAuthorize({ payer: buyer, amount: total, method: 'card', cardPw: req.body.cardPw });
            if (!auth.ok) return res.status(400).json({ error: '카드 승인 실패: ' + (auth.error || '') });
            pgApproval = auth.approvalNo;
        }
        // 거래내역은 상품별로 개별 기록 (환불 단위 = 1개 상품). rawDate에 마이크로초 오프셋으로 정렬 안정화.
        const _recordTxs = () => {
            items.forEach((it, idx) => {
                const itemRaw = new Date(now.getTime() + idx).toISOString();
                db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, pay_method, pg_approval) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [buyer, it.seller, it.productId, it.productName, Number(it.amount) || 0, it.purchaseType || 'original', itemRaw, dateStr, payMethod, pgApproval],
                    function(e) { if(idx === items.length - 1) res.json({ success: true, count: items.length, total, payMethod, approvalNo: pgApproval }); });
            });
        };
        db.serialize(() => {
            db.run('BEGIN IMMEDIATE');
            if (payMethod === 'card') {
                // 💳 외부 카드결제: 구매자 지갑 미차감, 판매자별 입금
                for (const s of sellers) db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [sellerSums[s], s]);
                db.run('COMMIT', () => _recordTxs());
            } else {
                // 잔액결제: 원자적 조건부 차감
                db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [total, buyer, total], function(ue) {
                    if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                    if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: `잔액 부족 (필요: ${total.toLocaleString()}원)` }); }
                    for (const s of sellers) db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [sellerSums[s], s]);
                    db.run('COMMIT', () => _recordTxs());
                });
            }
        });
        });
    };
    if (!_pids.length) return _afterPrice();
    db.all(`SELECT id, rx_form, price_original, price_stream FROM products WHERE id IN (${_pids.map(() => '?').join(',')})`, _pids, (pe, prows) => {
        const pm = {}; (prows || []).forEach(p => pm[p.id] = p);
        for (const it of items) {
            const prod = pm[it.productId];
            if (prod && !prod.rx_form) {
                it.amount = (it.purchaseType === 'stream') ? (Number(prod.price_stream) || Number(prod.price_original) || 0)
                                                            : (Number(prod.price_original) || Number(prod.price_stream) || 0);
            }
        }
        _afterPrice();
    });
});

function generateECCInverseSignature(checkId, secretKey, amount) {
    try {
        const hash = crypto.createHash('sha256').update(`${checkId}:${secretKey}:${amount}`).digest('hex');
        let inverseHex = ''; for (let i=0; i<hash.length; i++) inverseHex += (15 - parseInt(hash[i], 16)).toString(16);
        const sign = crypto.createSign('SHA256'); sign.update(inverseHex); return sign.sign(privateKey, 'hex');
    } catch(e){return '';}
}

app.post('/api/check/issue', (req, res) => {
    const issuer = requireUser(req, res); if (!issuer) return;   // ★신원=토큰(본문 issuer 무시)
    const amount = Number(req.body.amount) || 0;
    if (amount <= 0) return res.status(400).json({ error: '발행 금액이 올바르지 않습니다.' });
    const checkId = 'META_QR_' + Date.now(); const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
    const signature = generateECCInverseSignature(checkId, secretKey, amount); const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
    // 원자적 조건부 차감(잔액 부족 시 발행 안 됨)
    db.serialize(() => {
        db.run('BEGIN IMMEDIATE');
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [amount, issuer, amount], function(ue) {
            if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
            if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '발행 한도 초과' }); }
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`, [checkId, amount, issuer, secretKey, signature, date]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, rawDate, date) VALUES (?, ?, ?, ?, ?, ?)`, [issuer, 'Earth(Root)', '보안 수표 발행', amount, rawDate, date]);
            db.run('COMMIT', () => res.json({ success: true, checkId, secretKey, signature }));
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const redeemer = requireUser(req, res); if (!redeemer) return;   // ★신원=토큰(본문 redeemer 무시)
    const { checkId, secretKey } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`; let params = [checkId];
    if (secretKey && !checkId) { query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`; params = [secretKey]; }
    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "이미 회수되었거나 무효한 핀입니다." });
        const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
        // 원자적 회수: is_used 조건부 플립으로 이중 회수 차단
        db.serialize(() => {
            db.run('BEGIN IMMEDIATE');
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ? AND is_used = 0`, [row.id], function(ue) {
                if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 회수된 핀입니다.' }); }
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
                db.run(`INSERT INTO transactions (buyer, seller, productName, amount, rawDate, date) VALUES (?, ?, ?, ?, ?, ?)`, ['Earth(Root)', redeemer, '보안 수표 환원 충전', row.amount, rawDate, date]);
                db.run('COMMIT', () => res.json({ success: true, amount: row.amount }));
            });
        });
    });
});

app.post('/api/favorite/toggle', (req, res) => {
    const userName = requireUser(req, res); if (!userName) return;   // 🔐 신원=토큰(본문 userName 무시)
    db.get(`SELECT * FROM favorite_stores WHERE userName = ? AND targetStore = ?`, [userName, req.body.targetStore], (err, row) => {
        if(row) { db.run(`DELETE FROM favorite_stores WHERE id = ?`, [row.id], () => res.json({ success: true })); }
        else { db.run(`INSERT INTO favorite_stores (userName, targetStore) VALUES (?, ?)`, [userName, req.body.targetStore], () => res.json({ success: true })); }
    });
});
app.get('/api/favorites/:userName', (req, res) => { db.all(`SELECT targetStore FROM favorite_stores WHERE userName = ?`, [req.params.userName], (err, rows) => res.json(rows ? rows.map(r => r.targetStore) : [])); });

// 🦷 [기공소] 상점 보철 품목/수가 조회·저장(상세 의뢰서 취급 품목·자동 수가)
app.get('/api/store/rx-items/:storeId', (req, res) => {
    db.get(`SELECT id, name, category, rx_items FROM stores WHERE id = ?`, [req.params.storeId], (e, row) => {
        if (!row) return res.json({ storeId: req.params.storeId, storeName: '', items: [] });
        let items = []; try { items = row.rx_items ? JSON.parse(row.rx_items) : []; } catch (_) {}
        if ((!items || !items.length) && row.category === 'dental_lab') items = _defaultRxItems();
        res.json({ storeId: row.id, storeName: row.name, category: row.category, items });
    });
});
app.post('/api/store/rx-items', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    const { storeId, items } = req.body || {};
    if (!storeId) return res.status(400).json({ error: 'storeId 필요' });
    db.get(`SELECT owner FROM stores WHERE id = ?`, [storeId], (e, row) => {
        if (!row) return res.status(404).json({ error: '상점을 찾을 수 없음' });
        if (row.owner !== me && !isAdminName(me)) return res.status(403).json({ error: '상점 주인만 수정할 수 있습니다.' });
        const arr = Array.isArray(items) ? items.slice(0, 500).map(it => ({ tab:String(it.tab||'general'), category:String(it.category||''), name:String(it.name||''), price:_n(it.price), pontic:_n(it.pontic) })).filter(x => x.name) : [];
        db.run(`UPDATE stores SET rx_items = ? WHERE id = ?`, [JSON.stringify(arr), storeId], (ue) => ue ? res.status(500).json({ error: ue.message }) : res.json({ success: true, count: arr.length }));
    });
});
// ⚡ 채팅 히스토리: 최근 N개만 반환(무제한 SELECT + base64 첨부 전송으로 인한 로딩 지연 해결). before 커서로 이전 대화 더보기.
app.get('/api/chat/:roomId', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // 🔐 로그인 필수
    const roomId = String(req.params.roomId);
    const _serve = () => {
        const lim = Math.min(Number(req.query.limit) || 40, 100);
        const before = req.query.before ? Number(req.query.before) : null;
        const where = before ? `roomId = ? AND id < ?` : `roomId = ?`;
        const params = before ? [roomId, before] : [roomId];
        db.all(`SELECT * FROM (SELECT id, roomId, sender, senderPic, message, date FROM chats WHERE ${where} ORDER BY id DESC LIMIT ${lim}) ORDER BY id ASC`, params, (err, rows) => res.json(rows || []));
    };
    // 🔐 참가자만 열람. room_ord_는 chat_rooms의 buyer/seller, room_msg_는 roomId에 포함된 두 이름.
    if (isAdminName(me)) return _serve();
    if (roomId.startsWith('room_ord_')) {
        db.get(`SELECT buyer, seller FROM chat_rooms WHERE roomId = ?`, [roomId], (e, row) => {
            if (!row || (me !== row.buyer && me !== row.seller)) return res.status(403).json({ error: '참여한 대화방만 열람할 수 있습니다.' });
            _serve();
        });
    } else {
        const parts = roomId.replace('room_msg_', '').split('_').filter(Boolean);
        if (!parts.includes(me)) return res.status(403).json({ error: '참여한 대화방만 열람할 수 있습니다.' });
        _serve();
    }
});

// 💬 채팅 첨부 업로드 — 파일을 로컬 디스크에 저장하고 접근 URL 반환(메시지에 URL만 담아 재전송 방지)
app.post('/api/chat/attach', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // 🔐 로그인 필수(무인증 업로드 차단)
    try {
        const { filename, dataBase64 } = req.body || {};
        if (!dataBase64) return res.status(400).json({ error: '데이터가 없습니다.' });
        const buf = Buffer.from(String(dataBase64), 'base64');
        if (!buf.length) return res.status(400).json({ error: '빈 파일입니다.' });
        if (buf.length > 300 * 1024 * 1024) return res.status(413).json({ error: '파일이 너무 큽니다(300MB 초과).' });
        let ext = path.extname(String(filename || '')).slice(0, 12).replace(/[^.\w]/g, '');
        if (!ext) ext = '.bin';
        const safe = 'att_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex') + ext;
        // ☁️ R2 설정 시 R2로 업로드(무료 egress). 실패하면 로컬 디스크로 폴백.
        if (_r2) {
            const { PutObjectCommand } = require('@aws-sdk/client-s3');
            const ct = (req.body && req.body.mime) || _mimeFromExt(ext);
            _r2.client.send(new PutObjectCommand({ Bucket: _r2.bucket, Key: safe, Body: buf, ContentType: ct }))
                .then(() => res.json({ success: true, url: _r2.publicBase + '/' + safe, size: buf.length, store: 'r2' }))
                .catch((err) => {
                    console.warn('R2 업로드 실패 → 로컬 폴백:', err && err.message);
                    try { fs.writeFileSync(path.join(CHAT_UPLOAD_DIR, safe), buf); res.json({ success: true, url: _shareBaseUrl(req) + '/chat-files/' + safe, size: buf.length, store: 'local-fallback' }); }
                    catch (e2) { res.status(500).json({ error: (err && err.message) || 'R2 업로드 실패' }); }
                });
            return;
        }
        fs.writeFileSync(path.join(CHAT_UPLOAD_DIR, safe), buf);
        const url = _shareBaseUrl(req) + '/chat-files/' + safe;
        res.json({ success: true, url, size: buf.length });
    } catch (e) { res.status(500).json({ error: (e && e.message) || '업로드 실패' }); }
});

// 🚀 [v5] 내 구매 목록 (구매자 관점, 상품 메타 + 환불 상태 JOIN)
app.get('/api/purchases/:buyer', async (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.buyer)) return;   // 🔐 본인 구매내역만
    const buyer = req.params.buyer;
    try {
        // 자산 거래만 (환불/보너스/수표 발행 등 제외)
        const txs = await new Promise(r => db.all(
            `SELECT t.id as txId, t.buyer, t.seller, t.productId, t.productName, t.amount, t.purchaseType, t.date, t.rawDate, t.refunded,
                    p.thumbnail, p.is_package, p.package_data, p.description as product_description,
                    p.encryptedPayload, p.stream_time, p.stream_unit, p.price_stream, p.price_original, p.storeId,
                    (SELECT status FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refundStatus,
                    (SELECT id FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refundRequestId
             FROM transactions t
             LEFT JOIN products p ON t.productId = p.id
             WHERE t.buyer = ?
               AND t.purchaseType IS NOT NULL
               AND t.purchaseType != 'refund'
               AND t.purchaseType != 'signup_bonus'
               AND t.productId IS NOT NULL
             ORDER BY t.id DESC`,
            [buyer],
            (e, rows) => r(rows || [])
        ));

        // 각 구매에 연관된 주문서(product_orders) — ★N+1 제거★: 한 번에 조회 후 productId별 최신 주문 매핑(구매내역 로딩 가속)
        const orders = await new Promise(r => db.all(
            `SELECT id, productId, bundle_html, memo, form_data, created_at, courier, tracking, status FROM product_orders WHERE buyer = ? ORDER BY id DESC`,
            [buyer], (e, rows) => r(rows || [])
        ));
        const orderByPid = {};
        for(const o of orders) { if(!orderByPid[o.productId]) orderByPid[o.productId] = o; }   // id DESC → 첫 항목이 최신
        for(let t of txs) {
            const order = orderByPid[t.productId];
            if(order) {
                t.orderId = order.id;
                t.orderMemo = order.memo;
                t.orderFormData = order.form_data;
                t.orderCreatedAt = order.created_at;
                t.hasBundle = !!order.bundle_html;
                t.courier = order.courier; t.tracking = order.tracking; t.orderStatus = order.status;   // 🚚 배송조회용
            }
        }
        res.json(txs);
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// 🚀 [v5] 특정 주문의 bundle_html 만 가져오기 (재다운로드용)
app.get('/api/order/bundle/:orderId', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.get(`SELECT bundle_html, productId, buyer, seller FROM product_orders WHERE id = ?`, [req.params.orderId], (err, row) => {
        if(err || !row) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if (me !== row.buyer && me !== row.seller && !isAdminName(me)) return res.status(403).json({ error: '본인 주문만 조회할 수 있습니다.' });   // 🔐 당사자/관리자만
        res.json(row);
    });
});

app.get('/api/transactions/:name', async (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.name)) return;   // 🔐 본인 거래내역만
    const name = req.params.name;
    try {
        // 🚀 환불 요청 상태 + 상품·상점 정보 JOIN
        const txQuery = `SELECT t.*,
            (SELECT status FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refund_status,
            (SELECT id FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refund_request_id,
            p.is_package as p_is_package, p.package_data as p_package_data, p.storeId as p_storeId,
            (SELECT escrow_held FROM product_orders WHERE txId = t.id LIMIT 1) as escrowHeld,
            (SELECT settled FROM product_orders WHERE txId = t.id LIMIT 1) as orderSettled,
            (SELECT status FROM product_orders WHERE txId = t.id LIMIT 1) as orderStatus,
            s.name as storeName, s.category as storeCategory,
            (SELECT realname FROM users WHERE name = t.seller) as sellerRealname,
            (SELECT realname FROM users WHERE name = t.buyer) as buyerRealname
            FROM transactions t
            LEFT JOIN products p ON t.productId = p.id
            LEFT JOIN stores s ON p.storeId = s.id
            WHERE t.buyer=? OR t.seller=?`;
        const txs = await new Promise(r => db.all(txQuery, [name, name], (e, rows) => r(rows||[])));
        const tfs = await new Promise(r => db.all(`SELECT * FROM transfers WHERE sender=? OR receiver=?`, [name, name], (e, rows) => r(rows||[])));
        const dps = await new Promise(r => db.all(`SELECT * FROM deposits WHERE user_name=?`, [name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));

        let history = [];
        txs.forEach(t => {
            const isBuyer = t.buyer === name;
            const escrowHeld = t.escrowHeld || 0;   // 💰 Admin 에스크로(통합관리) 판매 여부
            // (에스크로 판매도 판매자 거래내역에 '판매' 행으로 표시 → 각 행에 매출/정산 상태 표기)
            const refStatus = t.refund_status;
            const refundable = isBuyer && !t.refunded && refStatus !== 'pending'
                && escrowHeld === 0   // 에스크로 구매는 주문(구매내역/채팅카드)에서 환불 요청 — 거래내역 환불 버튼 비활성
                && t.productId && t.purchaseType !== 'refund' && t.purchaseType !== 'signup_bonus'
                && !['보안 수표 발행', '보안 수표 환원 충전', '신규 가입 정산 한도 축하금'].includes(t.productName);
            let baseType;
            if(t.purchaseType === 'refund') baseType = isBuyer ? '환불 수령' : '환불 지급';
            else if(t.purchaseType === 'signup_bonus') baseType = '가입 축하금';
            else if(t.productName === '보안 수표 발행') baseType = '보안 수표 발행';
            else if(t.productName === '보안 수표 환원 충전') baseType = '보안 수표 환원';
            else baseType = isBuyer ? '자산 구매' : '자산 판매';

            // 🚀 [v7] 패키지 상품이면 파일명 목록 추출
            let fileNames = [];
            try {
                if(t.p_is_package && t.p_package_data) {
                    const pkg = JSON.parse(t.p_package_data);
                    fileNames = (pkg.files || []).map(f => f.filename).filter(x => x).slice(0, 5);
                }
            } catch(e){}

            history.push({
                txId: t.id, type: baseType,
                date: t.date, rawDate: t.rawDate || t.date, productId: t.productId, purchaseType: t.purchaseType,
                amount: t.amount, productName: t.productName, buyer: t.buyer, seller: isBuyer ? t.seller : t.buyer,
                refunded: !!t.refunded, refundable, refundStatus: refStatus, refundRequestId: t.refund_request_id,
                storeName: t.storeName || null, storeId: t.p_storeId || null, fileNames: fileNames,
                makeKind: t.make_kind || null, storeCategory: t.storeCategory || null,   // 🦷 기공: 신규제작/리메이크/리페어
                isSeller: !isBuyer, escrowHeld: escrowHeld, settled: !!t.orderSettled, orderStatus: t.orderStatus || null,   // 💰 매출/정산 표기용
                refunded2: !!t.refunded,
                // 🧾 거래처 표기명(세금계산서와 통일): 상대방 실명(상호) → 없으면 브랜드 → ID
                counterpartyRealname: (isBuyer ? t.sellerRealname : t.buyerRealname) || null
            });
        });
        tfs.forEach(t => {
            let settle = null; try { if (t.memo) { const mo = JSON.parse(t.memo); if (mo && mo.kind === 'settlement') settle = mo; } } catch (_) {}
            if (settle && t.receiver === name) {
                // 💰 정산 입금 — 어떤 항목의 정산인지 상세(items)와 함께 하나의 기록으로 표시
                history.push({ type: '정산 입금', date: t.date, rawDate: t.rawDate || t.date, amount: t.amount,
                    seller: t.sender, sender: t.sender, receiver: t.receiver,
                    settle: { month: settle.month || '', salesTotal: settle.salesTotal || 0, payFee: settle.payFee || 0, payout: settle.payout || t.amount, items: settle.items || [] } });
            } else {
                history.push({ type: t.sender === name ? '송금 (출금)' : '송금 (입금)', date: t.date, rawDate: t.rawDate || t.date, amount: t.amount, seller: t.receiver || t.sender, sender: t.sender, receiver: t.receiver });
            }
        });
        dps.forEach(d => history.push({ type: `입금 신청 (${d.status})`, date: d.date, rawDate: d.rawDate || d.date, amount: d.amount, seller: 'Earth(Root)' }));
        wds.forEach(w => history.push({ type: `출금 집행 완료`, date: w.date, rawDate: w.rawDate || w.date, amount: w.amount, seller: '지정 등록 계좌' }));

        // 🚀 최신순 정렬 (rawDate 우선)
        history.sort((a,b) => {
            const da = new Date(a.rawDate || a.date).getTime() || 0;
            const dbb = new Date(b.rawDate || b.date).getTime() || 0;
            return dbb - da;
        });
        res.json(history);
    } catch(e) { res.json([]); }
});

// 🚀 환불 요청 (판매자 승인 대기 상태로 생성; 자금 이동 X)
app.post('/api/refund/request', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰(본문 requester 무시)
    const { txId, reason } = req.body;
    db.get(`SELECT * FROM transactions WHERE id = ?`, [txId], (err, tx) => {
        if(!tx) return res.status(404).json({ error: "거래 내역을 찾을 수 없습니다." });
        if(tx.buyer !== me) return res.status(403).json({ error: "구매자만 환불 요청할 수 있습니다." });
        if(tx.refunded) return res.status(400).json({ error: "이미 환불 처리된 거래입니다." });
        if(!tx.productId || tx.purchaseType === 'refund' || ['보안 수표 발행', '보안 수표 환원 충전'].includes(tx.productName)) {
            return res.status(400).json({ error: "해당 거래 유형은 환불할 수 없습니다." });
        }
        // 🔒 에스크로/구매확정/정산 주문은 이 경로 금지 — 주문 상세(/api/order/status)로만 환불.
        db.get(`SELECT id, status, escrow_held, settled FROM product_orders WHERE txId = ?`, [txId], (eo, ord) => {
            if (ord && (Number(ord.escrow_held) > 0 || ord.settled || ['confirmed', 'settled'].includes(ord.status))) {
                return res.status(400).json({ error: "에스크로/구매확정 주문은 주문 상세에서 환불 요청해 주세요." });
            }
            db.get(`SELECT * FROM refund_requests WHERE txId = ? AND status = 'pending'`, [txId], (e2, existing) => {
                if(existing) return res.status(400).json({ error: "이미 환불 요청이 진행 중입니다. (판매자 승인 대기)" });
                const date = new Date().toLocaleString('ko-KR');
                db.run(`INSERT INTO refund_requests (txId, buyer, seller, productId, productName, amount, status, reason, request_date) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
                    [txId, tx.buyer, tx.seller, tx.productId, tx.productName, tx.amount, reason || '', date],
                    function(err3) {
                        if(err3) return res.status(500).json({ error: err3.message });
                        res.json({ success: true, requestId: this.lastID });
                    });
            });
        });
    });
});

// 🚀 판매자에게 들어온 환불 요청 (승인/거절 대기)
app.get('/api/refunds/incoming/:name', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.name)) return;   // 🔐 본인에게 온 환불요청만
    db.all(`SELECT * FROM refund_requests WHERE seller = ? AND status = 'pending' ORDER BY id DESC`, [req.params.name], (err, rows) => res.json(rows || []));
});
// 🚀 구매자가 보낸 모든 환불 요청 이력
app.get('/api/refunds/outgoing/:name', (req, res) => {
    if (!requireSelfOrAdmin(req, res, req.params.name)) return;   // 🔐 본인이 보낸 환불요청만
    db.all(`SELECT * FROM refund_requests WHERE buyer = ? ORDER BY id DESC`, [req.params.name], (err, rows) => res.json(rows || []));
});

// 🚀 판매자가 환불 승인/거절
app.post('/api/refund/decide', (req, res) => {
    const me = requireUser(req, res); if (!me) return;   // ★신원=토큰(본문 decider 무시)
    const { requestId, decision } = req.body; // decision: 'approve' | 'reject'
    db.get(`SELECT * FROM refund_requests WHERE id = ?`, [requestId], (err, rq) => {
        if(!rq) return res.status(404).json({ error: '환불 요청을 찾을 수 없습니다.' });
        if(rq.seller !== me) return res.status(403).json({ error: '판매자만 결정할 수 있습니다.' });   // DB의 seller와 토큰 신원 대조
        if(rq.status !== 'pending') return res.status(400).json({ error: '이미 처리된 요청입니다.' });
        const date = new Date().toLocaleString('ko-KR');
        if(decision === 'reject') {
            db.run(`UPDATE refund_requests SET status = 'rejected', decision_date = ? WHERE id = ? AND status = 'pending'`, [date, requestId], () => res.json({ success: true, status: 'rejected' }));
        } else if(decision === 'approve') {
            // 🔒 에스크로/구매확정/정산 주문은 이 경로 금지(→ /api/order/status).
            db.get(`SELECT escrow_held, settled, status FROM product_orders WHERE txId = ?`, [rq.txId], (eo, ord) => {
                if (ord && (Number(ord.escrow_held) > 0 || ord.settled || ['confirmed', 'settled'].includes(ord.status))) {
                    return res.status(400).json({ error: '에스크로/구매확정 주문은 주문 상세에서 처리해 주세요.' });
                }
                const rawDate = new Date().toISOString();
                db.serialize(() => {
                    db.run('BEGIN IMMEDIATE');
                    // 요청 상태 원자적 확정(이중 환불 차단)
                    db.run(`UPDATE refund_requests SET status = 'approved', decision_date = ? WHERE id = ? AND status = 'pending'`, [date, requestId], function(fe) {
                        if (fe) { db.run('ROLLBACK'); return res.status(500).json({ error: fe.message }); }
                        if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 처리된 요청입니다.' }); }
                        // 판매자 → 구매자 환불(원자적 조건부 차감)
                        db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [rq.amount, rq.seller, rq.amount], function(ue) {
                            if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                            if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '잔액 부족으로 환불 승인 불가' }); }
                            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [rq.amount, rq.buyer]);
                            db.run(`UPDATE transactions SET refunded = 1 WHERE id = ?`, [rq.txId]);
                            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, refunded) VALUES (?, ?, ?, ?, ?, 'refund', ?, ?, 1)`,
                                [rq.seller, rq.buyer, rq.productId, `[환불] ${rq.productName}`, rq.amount, rawDate, date]);
                            db.run('COMMIT', () => res.json({ success: true, status: 'approved', amount: rq.amount }));
                        });
                    });
                });
            });
        } else {
            res.status(400).json({ error: '결정 유형이 올바르지 않습니다.' });
        }
    });
});

// 🚀 레거시 호환: /api/refund 요청을 새 요청 흐름으로 라우팅 (즉시 처리가 아닌 승인 대기 생성)
app.post('/api/refund', (req, res) => {
    // Express 5에서 app._router.handle 제거됨 → 307 리다이렉트로 새 흐름 라우팅(본문/메서드 보존)
    res.redirect(307, '/api/refund/request');
});

// ============================================================================================
// 🧾 전자세금계산서 + 정산(배민식: Admin 단독 일괄) — 팍스빌 ASP 어댑터(기본 Mock, env로 live 전환)
//  정산 공식: 매출 - 결제수수료(2.7%) - SW월사용료(10000) - 그 수수료합의 VAT(10%). 세 값은 settings로 변경 가능.
//  국세청 전송 API(팍스빌)가 없으면 Mock으로 발행 기록만 남기고 프런트에서 PDF 출력. 계약 후 env 넣으면 live.
// ============================================================================================
function _digits(v){ return String(v == null ? '' : v).replace(/\D/g, ''); }
function _n(v){ return Math.max(0, Math.round(Number(v) || 0)); }
function _taxNow(){ return new Date().toISOString(); }
function _isLivePaxbill(){ return String(process.env.PAXBILL_MODE||'').toLowerCase()==='live' && !!process.env.PAXBILL_API_BASE && !!process.env.PAXBILL_API_KEY; }
function _paxbillStatus(){ return { mode: _isLivePaxbill()?'live':'mock', baseSet: !!process.env.PAXBILL_API_BASE, issuePath: process.env.PAXBILL_ISSUE_PATH||'/tax-invoices/issue-and-send', statusPath: process.env.PAXBILL_STATUS_PATH||'/tax-invoices/status' }; }
async function _postToPaxbill(pathKey, payload){
    const st = _paxbillStatus();
    if (st.mode !== 'live') {
        const id = 'MOCK-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
        return { ok:true, mock:true, invoiceNo:id, issueStatus:'issued', ntsStatus:'nts_sent_mock', message:'테스트 모드: 실제 팍스빌/국세청 전송은 수행하지 않았습니다.' };
    }
    if (typeof fetch !== 'function') throw new Error('Node 18+ 또는 node-fetch 필요(fetch 없음)');
    const path = pathKey === 'status' ? st.statusPath : st.issuePath;
    const base = String(process.env.PAXBILL_API_BASE).replace(/\/$/, '');
    const url = base + (path.startsWith('/') ? path : '/' + path);
    const r = await fetch(url, { method:'POST', headers:{ 'Content-Type':'application/json', 'Accept':'application/json', 'Authorization':`Bearer ${process.env.PAXBILL_API_KEY}`, 'X-Paxbill-Secret':process.env.PAXBILL_SECRET||'' }, body: JSON.stringify(payload) });
    const txt = await r.text(); let data; try { data = JSON.parse(txt); } catch(_) { data = { raw: txt }; }
    if (!r.ok) throw new Error('팍스빌 API 오류: ' + ((data && (data.message||data.error||data.raw)) || ('HTTP ' + r.status)));
    return Object.assign({ ok:true, mock:false }, data || {});
}
// 정산 변수 조회(신규: 카드결제 수수료율 2.4% + 거래 수수료율 0.6%. SW월사용료·VAT 폐지)
function _taxConfig(cb){
    db.all(`SELECT key,value FROM settings WHERE key IN ('tax_card_fee_rate','tax_txn_fee_rate')`, [], (e, rows) => {
        const m = {}; (rows||[]).forEach(r => m[r.key] = r.value);
        let cardFeeRate = parseFloat(m.tax_card_fee_rate); if (isNaN(cardFeeRate)) cardFeeRate = 2.4;
        let txnFeeRate  = parseFloat(m.tax_txn_fee_rate);  if (isNaN(txnFeeRate))  txnFeeRate = 0.6;
        cb({ cardFeeRate, txnFeeRate, payFeeRate: cardFeeRate + txnFeeRate });
    });
}
// 매출 → 정산 내역 계산. 결제수수료 = (카드율+거래율)%, 지급액 = 매출 − 결제수수료. VAT·SW 없음.
//  예) 매출 10000, 카드2.4+거래0.6=3% → 결제수수료 300, 지급액 9700. (수수료 300은 Admin 매출로 귀속)
function _settleCalc(salesTotal, cfg){
    salesTotal = _n(salesTotal);
    // 🔧 수수료율은 소수(2.4/0.6)이므로 절대 반올림(_n) 금지 — 금액만 반올림. (예전 _n(2.4)=2, _n(0.6)=1 로 요율 왜곡)
    let cardRate = parseFloat(cfg.cardFeeRate); if (isNaN(cardRate)) cardRate = 0;
    let txnRate  = parseFloat(cfg.txnFeeRate);  if (isNaN(txnRate))  txnRate = 0;
    const cardFee = Math.round(salesTotal * cardRate / 100);
    const txnFee  = Math.round(salesTotal * txnRate / 100);
    const payFee  = cardFee + txnFee;                    // 결제수수료(=Admin 수수료 수입)
    const payout  = salesTotal - payFee;                 // 상점 지급액
    // 하위호환 필드(commissionTotal/feeSubtotal=수수료, vatOnFees/swFee=0)
    return { salesTotal, cardFee, txnFee, payFee, feeRate: cardRate + txnRate, payout, commissionTotal: payFee, feeSubtotal: payFee, vatOnFees: 0, swFee: 0 };
}
const _salesWhere = `t.productId IS NOT NULL AND IFNULL(t.refunded,0)=0 AND t.purchaseType IS NOT NULL AND t.purchaseType NOT IN ('refund','signup_bonus')`;

// 팍스빌 연동 모드(live/mock)
app.get('/api/tax/config/status', (req, res) => { res.json(_paxbillStatus()); });
// 정산 변수 조회/변경(Admin)
app.get('/api/tax/config', (req, res) => { _taxConfig(cfg => res.json(cfg)); });
app.post('/api/tax/config', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const map = { tax_card_fee_rate: req.body.cardFeeRate, tax_txn_fee_rate: req.body.txnFeeRate };
    const entries = Object.entries(map).filter(([k, v]) => v != null && v !== '');
    if (!entries.length) return _taxConfig(cfg => res.json({ success: true, config: cfg }));
    let n = 0; entries.forEach(([k, v]) => db.run(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [k, String(v)], () => { if (++n === entries.length) _taxConfig(cfg => res.json({ success: true, config: cfg })); }));
});
// 🏬 [상점 관리] Admin: 등록된 상점 목록/검색 + Admin 통합관리(admin_managed) 여부. 체크 시 해당 상점은 에스크로/정산 대상.
app.get('/api/admin/stores', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const q = String(req.query.q || '').trim();
    let where = `1=1`; const params = [];
    if (q) { where += ` AND (s.name LIKE ? OR s.owner LIKE ? OR IFNULL(s.bizNo,'') LIKE ?)`; const like = '%' + q + '%'; params.push(like, like, like); }
    db.all(`SELECT s.id, s.name, s.owner, s.status, s.bizType, s.bizNo, IFNULL(s.admin_managed,0) admin_managed,
                   (SELECT realname FROM users WHERE name = s.owner) ownerRealname,
                   (SELECT COUNT(*) FROM products p WHERE p.storeId = s.id) productCount
            FROM stores s WHERE ${where} ORDER BY s.admin_managed DESC, s.name ASC LIMIT 500`, params,
        (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json({ stores: rows || [] }));
});
app.post('/api/admin/store/manage', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { storeId, managed } = req.body || {};
    if (!storeId) return res.status(400).json({ error: 'storeId 필요' });
    db.run(`UPDATE stores SET admin_managed = ? WHERE id = ?`, [managed ? 1 : 0, storeId],
        function(err) { if (err) return res.status(500).json({ error: err.message }); res.json({ success: true, storeId, managed: managed ? 1 : 0, changed: this.changes }); });
});
// 👑 [관리자] 전체 상품 주문(판매 상태) 조회 — 상태/검색 필터. 모든 상점의 주문을 상태와 함께.
app.get('/api/admin/orders', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const status = String(req.query.status || '').trim();
    const q = String(req.query.q || '').trim();
    let where = `1=1`; const params = [];
    if (status) { where += ` AND o.status = ?`; params.push(status); }
    if (q) { where += ` AND (o.buyer LIKE ? OR o.seller LIKE ? OR IFNULL(pr.name,'') LIKE ? OR IFNULL(s.name,'') LIKE ?)`; const like = '%' + q + '%'; params.push(like, like, like, like); }
    db.all(`SELECT o.id, o.productId, o.buyer, o.seller, o.status, o.amount, o.tracking, o.courier,
                   o.created_at, o.delivered_at, o.confirmed_at, o.escrow_held, o.settled, o.settled_at, o.settle_month, o.txId,
                   pr.name AS productName, s.name AS storeName, IFNULL(s.admin_managed,0) AS storeManaged,
                   (SELECT realname FROM users WHERE name = o.buyer) AS buyerRealname
            FROM product_orders o
            LEFT JOIN products pr ON pr.id = o.productId
            LEFT JOIN stores s ON pr.storeId = s.id
            WHERE ${where} ORDER BY o.id DESC LIMIT 1000`, params,
        (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json({ orders: rows || [] }));
});
// 👑 [관리자] 전체 거래내역 조회 — 모든 사용자/상점의 거래.
app.get('/api/admin/transactions', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const q = String(req.query.q || '').trim();
    const month = String(req.query.month || '').slice(0, 7);
    let where = `1=1`; const params = [];
    if (q) { where += ` AND (t.buyer LIKE ? OR t.seller LIKE ? OR IFNULL(t.productName,'') LIKE ?)`; const like = '%' + q + '%'; params.push(like, like, like); }
    if (month) { where += ` AND substr(IFNULL(t.rawDate,t.date),1,7) = ?`; params.push(month); }
    db.all(`SELECT t.id, t.buyer, t.seller, t.productId, t.productName, t.amount, t.purchaseType, t.date, t.rawDate, IFNULL(t.refunded,0) refunded
            FROM transactions t WHERE ${where} ORDER BY t.id DESC LIMIT 2000`, params,
        (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json({ transactions: rows || [] }));
});
// 🧾 공급자(플랫폼) 정보 서버 영속화 — 항상 마지막 입력값 자동 저장(settings.tax_supplier JSON). 프런트 localStorage와 병행.
app.get('/api/tax/supplier', (req, res) => {
    db.get(`SELECT value FROM settings WHERE key='tax_supplier'`, [], (e, row) => {
        let obj = null; try { obj = row && row.value ? JSON.parse(row.value) : null; } catch (_) {}
        res.json({ supplier: obj });
    });
});
app.post('/api/tax/supplier', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const sup = req.body && req.body.supplier ? req.body.supplier : req.body;
    let json = ''; try { json = JSON.stringify(sup || {}); } catch (_) { json = ''; }
    db.run(`INSERT INTO settings(key,value) VALUES('tax_supplier',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [json],
        (err) => err ? res.status(500).json({ error: err.message }) : res.json({ success: true }));
});
// Admin: 전체 업체 판매내역(월 선택)
app.get('/api/admin/tax/sales', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const month = String(req.query.month || '').slice(0, 7);
    let where = _salesWhere; const params = [];
    if (month) { where += ` AND substr(IFNULL(t.rawDate,t.date),1,7)=?`; params.push(month); }
    db.all(`SELECT t.id txId, t.seller, t.buyer, t.productName, t.amount, t.date, t.rawDate,
                   u.realname buyerRealname, u.email buyerEmail
            FROM transactions t LEFT JOIN users u ON t.buyer=u.name
            WHERE ${where} ORDER BY t.id DESC LIMIT 1000`, params, (err, rows) => err ? res.status(500).json({ error: err.message }) : res.json(rows || []));
});
// Admin: 상점별 정산(구매확정된 에스크로 주문 기준). 매출=확정·미정산 주문 합계, 결제수수료·지급액 계산.
//  admin_managed 상점만(escrow_held>0). 정산월=구매확정 귀속월(settle_month).
app.get('/api/admin/tax/settlement', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const month = String(req.query.month || '').slice(0, 7);
    const owner = String(req.query.owner || '').trim();   // 특정 상점주만(선택)
    _taxConfig((cfg) => {
        let where = `o.status='confirmed' AND o.escrow_held>0 AND o.settled=0`; const params = [];
        if (month) { where += ` AND o.settle_month=?`; params.push(month); }
        if (owner) { where += ` AND o.seller=?`; params.push(owner); }
        db.all(`SELECT o.seller, COUNT(*) cnt, SUM(o.escrow_held) salesTotal,
                    su.realname sellerRealname, su.biz_no su_bizno, su.biz_company su_company, su.biz_ceo su_ceo,
                    su.biz_addr su_addr, su.biz_industry su_industry, su.biz_item su_item, su.tax_email su_taxemail, su.email su_email,
                    GROUP_CONCAT(DISTINCT p.storeId) storeIds,
                    GROUP_CONCAT(DISTINCT s.name) brands,
                    GROUP_CONCAT(DISTINCT s.bizNo) bizNos
                FROM product_orders o
                LEFT JOIN products p ON p.id = o.productId
                LEFT JOIN stores s ON p.storeId = s.id
                LEFT JOIN users su ON su.name = o.seller
                WHERE ${where} GROUP BY o.seller ORDER BY salesTotal DESC`, params, (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            const vendors = (rows || []).map(r => Object.assign({
                seller: r.seller, count: r.cnt,
                bizName: (r.su_company && r.su_company.trim()) || (r.sellerRealname && r.sellerRealname.trim()) || (r.brands ? String(r.brands).split(',')[0] : '') || r.seller,
                bizNo: r.su_bizno || (r.bizNos ? String(r.bizNos).split(',')[0] : ''),
                bizCeo: r.su_ceo || r.sellerRealname || '', bizAddr: r.su_addr || '', bizIndustry: r.su_industry || '', bizItem: r.su_item || '', taxEmail: r.su_taxemail || r.su_email || '',
                storeIds: r.storeIds || '', brands: r.brands || ''
            }, _settleCalc(r.salesTotal, cfg)));
            const adminRevenue = vendors.reduce((s, v) => s + (v.payFee || 0), 0);   // 거래 수수료 = Admin 매출
            res.json({ month, config: cfg, vendors, adminRevenue });
        });
    });
});
// Admin: 정산 완료(settled=1) 상점별 목록 — 세금계산서 발행 대상. settlement과 동일 그룹/계산, settled=1 기준.
app.get('/api/admin/tax/settled', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const month = String(req.query.month || '').slice(0, 7);
    const owner = String(req.query.owner || '').trim();
    _taxConfig((cfg) => {
        let where = `o.settled=1 AND o.escrow_held>0`; const params = [];
        if (month) { where += ` AND o.settle_month=?`; params.push(month); }
        if (owner) { where += ` AND o.seller=?`; params.push(owner); }
        db.all(`SELECT o.seller, COUNT(*) cnt, SUM(o.escrow_held) salesTotal, MAX(o.settled_at) settledAt,
                    su.realname sellerRealname, su.biz_no su_bizno, su.biz_company su_company, su.biz_ceo su_ceo,
                    su.biz_addr su_addr, su.biz_industry su_industry, su.biz_item su_item, su.tax_email su_taxemail, su.email su_email,
                    GROUP_CONCAT(DISTINCT p.storeId) storeIds,
                    GROUP_CONCAT(DISTINCT s.name) brands,
                    GROUP_CONCAT(DISTINCT s.bizNo) bizNos
                FROM product_orders o
                LEFT JOIN products p ON p.id = o.productId
                LEFT JOIN stores s ON p.storeId = s.id
                LEFT JOIN users su ON su.name = o.seller
                WHERE ${where} GROUP BY o.seller ORDER BY salesTotal DESC`, params, (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            const vendors = (rows || []).map(r => Object.assign({
                seller: r.seller, count: r.cnt, settledAt: r.settledAt || '',
                bizName: (r.su_company && r.su_company.trim()) || (r.sellerRealname && r.sellerRealname.trim()) || (r.brands ? String(r.brands).split(',')[0] : '') || r.seller,
                bizNo: r.su_bizno || (r.bizNos ? String(r.bizNos).split(',')[0] : ''),
                bizCeo: r.su_ceo || r.sellerRealname || '', bizAddr: r.su_addr || '', bizIndustry: r.su_industry || '', bizItem: r.su_item || '', taxEmail: r.su_taxemail || r.su_email || '',
                storeIds: r.storeIds || '', brands: r.brands || ''
            }, _settleCalc(r.salesTotal, cfg)));
            const adminRevenue = vendors.reduce((s, v) => s + (v.payFee || 0), 0);
            res.json({ month, config: cfg, vendors, adminRevenue });
        });
    });
});
// 💰 Admin: 정산 실행 — 확정·미정산 주문의 지급액(매출−결제수수료)을 Admin→상점주 계정으로 이체, 주문 settled=1. 수수료는 Admin 매출로 잔류.
app.post('/api/tax/settle', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const seller = String(req.body.seller || '').trim();
    const month = String(req.body.month || '').slice(0, 7);
    if (!seller) return res.status(400).json({ error: '정산 대상 상점(seller)이 없습니다.' });
    _taxConfig((cfg) => {
        let where = `o.status='confirmed' AND o.escrow_held>0 AND o.settled=0 AND o.seller=?`; const params = [seller];
        if (month) { where += ` AND o.settle_month=?`; params.push(month); }
        db.all(`SELECT o.id, o.escrow_held, o.buyer, pr.name AS productName FROM product_orders o LEFT JOIN products pr ON pr.id = o.productId WHERE ${where}`, params, (e, rows) => {
            if (e) return res.status(500).json({ error: e.message });
            if (!rows || !rows.length) return res.status(400).json({ error: '정산할 구매확정 주문이 없습니다.' });
            const salesTotal = rows.reduce((s, r) => s + (r.escrow_held || 0), 0);
            const calc = _settleCalc(salesTotal, cfg);
            const admin = _adminAccount();
            const payout = calc.payout;
            const ids = rows.map(r => r.id);
            const raw = new Date().toISOString();
            // 💰 정산 입금 상세(거래내역에서 '어떤 항목의 정산인지' 표시용): 포함된 판매 항목 리스트
            const settleMemo = JSON.stringify({ kind: 'settlement', month: month || '', salesTotal, payFee: calc.payFee, payout,
                items: rows.map(r => ({ orderId: r.id, name: r.productName || r.id, buyer: r.buyer, amount: r.escrow_held || 0 })) });
            // 💰 본인(Admin) 상점 정산: 자금이 이미 Admin 지갑에 있으므로 자기이체 없이 주문만 settled 처리(수수료·지급 개념 미적용, 전액 Admin 귀속).
            if (seller === admin) {
                // 자기 상점: 자금 이동 없이 settled 플립만. 이미 정산된 건은 제외(AND settled=0) + 이중정산 차단.
                db.serialize(() => {
                    db.run('BEGIN IMMEDIATE');
                    db.run(`UPDATE product_orders SET settled = 1, settled_at = ? WHERE settled = 0 AND id IN (${ids.map(() => '?').join(',')})`, [raw, ...ids], function(ue) {
                        if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                        if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 정산된 주문입니다.' }); }
                        db.run('COMMIT', () => res.json({ success: true, seller, selfStore: true, count: rows.length, salesTotal, payFee: 0, payout: salesTotal, adminRevenue: 0 }));
                    });
                });
                return;
            }
            db.serialize(() => {
                db.run('BEGIN IMMEDIATE');
                // 이중 정산 차단: settled=0 조건부 플립을 먼저 수행(이미 정산됐으면 this.changes===0 → 롤백).
                db.run(`UPDATE product_orders SET settled = 1, settled_at = ? WHERE settled = 0 AND id IN (${ids.map(() => '?').join(',')})`, [raw, ...ids], function(fe) {
                    if (fe) { db.run('ROLLBACK'); return res.status(500).json({ error: fe.message }); }
                    if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: '이미 정산된 주문입니다.' }); }
                    db.run(`UPDATE users SET balance = balance - ? WHERE name = ? AND balance >= ?`, [payout, admin, payout], function(ue) {
                        if (ue) { db.run('ROLLBACK'); return res.status(500).json({ error: ue.message }); }
                        if (this.changes === 0) { db.run('ROLLBACK'); return res.status(400).json({ error: 'Admin 보관 잔액이 부족합니다.' }); }
                        // 판매자 계정에 실제로 입금됐는지 확인(계정 없으면 롤백) — 지급 누락/무효 이체 방지.
                        db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [payout, seller], function(ce) {
                            if (ce) { db.run('ROLLBACK'); return res.status(500).json({ error: ce.message }); }
                            if (this.changes === 0) { db.run('ROLLBACK'); return res.status(404).json({ error: '정산 대상 상점 계정을 찾을 수 없습니다.' }); }
                            const now = new Date().toLocaleString('ko-KR');
                            db.run(`INSERT INTO transfers (sender, receiver, amount, date, rawDate, memo) VALUES (?, ?, ?, ?, ?, ?)`, [admin, seller, payout, now, raw, settleMemo]);
                            db.run('COMMIT', () => res.json({ success: true, seller, count: rows.length, salesTotal, payFee: calc.payFee, payout, adminRevenue: calc.payFee }));
                        });
                    });
                });
            });
        });
    });
});
// Admin: 발행 이력 전체(월/업체 필터)
app.get('/api/admin/tax/invoices', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const month = String(req.query.month || '').slice(0, 7);
    let where = '1=1'; const params = [];
    if (month) { where += ` AND batchMonth=?`; params.push(month); }
    db.all(`SELECT * FROM tax_invoices WHERE ${where} ORDER BY id DESC LIMIT 500`, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json((rows || []).map(r => { let p = {}; try { p = JSON.parse(r.payload || '{}'); } catch(_){} return Object.assign({}, r, { payloadObj: p }); }));
    });
});
// 세금계산서 1건 발행(Admin이 특정 업체 커미션 세금계산서 발행). transactionId 없음(월 정산 커미션).
async function _issueOne(body){
    const b = body || {};
    const seller = String(b.seller || '').trim();            // 공급받는자(업체)
    const supplier = b.supplier || {};                        // 공급자(플랫폼/Admin)
    const recipient = b.recipient || { name: seller };        // 공급받는자(업체)
    // 🧾 품목(최대 16). items 배열이 오면 그대로, 없으면 단일 item(하위호환)으로 구성.
    const _mkItem = (it) => { it = it || {}; const s = _n(it.supplyAmount), t = _n(it.taxAmount); let tot = _n(it.totalAmount); if (!tot) tot = s + t;
        return { month: String(it.month||''), day: String(it.day||''), name:String(it.name||''), spec:String(it.spec||''), qty:(it.qty===''||it.qty==null)?'':Number(it.qty), unitPrice:_n(it.unitPrice), supplyAmount:s, taxAmount:t, totalAmount:tot, remark:String(it.remark||'') }; };
    let items = (Array.isArray(b.items) && b.items.length) ? b.items.map(_mkItem).filter(x => x.name || x.supplyAmount || x.totalAmount) : null;
    if (!items || !items.length) { const item = b.item || {}; items = [_mkItem({ name: item.name || '플랫폼 이용 수수료', spec:item.spec, qty:item.qty||1, supplyAmount: (b.supplyAmount!=null?b.supplyAmount:item.supplyAmount), taxAmount: (b.taxAmount!=null?b.taxAmount:item.taxAmount), totalAmount: (b.totalAmount!=null?b.totalAmount:item.totalAmount), remark:item.remark })]; }
    if (items.length > 16) items = items.slice(0, 16);
    // 합계: 명시 총액이 오면 사용, 아니면 품목 합.
    let supplyAmount = (b.supplyAmount != null) ? _n(b.supplyAmount) : items.reduce((s, it) => s + it.supplyAmount, 0);
    let taxAmount = (b.taxAmount != null) ? _n(b.taxAmount) : items.reduce((s, it) => s + it.taxAmount, 0);
    let totalAmount = (b.totalAmount != null) ? _n(b.totalAmount) : items.reduce((s, it) => s + it.totalAmount, 0);
    if (!totalAmount) totalAmount = supplyAmount + taxAmount;
    if (!supplier.name || !_digits(supplier.bizNo)) throw new Error('공급자(플랫폼) 상호·사업자번호를 입력하세요.');
    if (totalAmount <= 0) throw new Error('발행 금액이 0원입니다.');
    const pay = b.payment || {};
    const payload = {
        documentType: (b.docType === 'invoice') ? 'invoice' : 'tax_invoice',   // 세금계산서 | 계산서(면세)
        issueType: b.issueType || 'normal',                 // 일반|영세율|위수탁|위수탁영세율
        recipientIdType: b.recipientIdType || 'biz',         // 공급받는자구분: biz|resident|foreign
        purposeType: b.purposeType || 'receipt',             // 영수(receipt) | 청구(claim)
        taxType: b.taxType || 'taxable',
        writeDate: b.writeDate || new Date().toISOString().slice(0, 10), supplyDate: b.supplyDate || null, sendToNts: true,
        seller, buyer: b.buyer || '', batchMonth: b.batchMonth || null,
        supplier: { bizNo:_digits(supplier.bizNo), subBizNo:String(supplier.subBizNo||''), name:String(supplier.name||''), ceoName:String(supplier.ceoName||''), address:String(supplier.address||''), bizType:String(supplier.bizType||''), bizClass:String(supplier.bizClass||''), email:String(supplier.email||''), phone:String(supplier.phone||'') },
        recipient: { bizNo:_digits(recipient.bizNo), subBizNo:String(recipient.subBizNo||''), name:String(recipient.name||seller), ceoName:String(recipient.ceoName||''), address:String(recipient.address||''), bizType:String(recipient.bizType||''), bizClass:String(recipient.bizClass||''), email:String(recipient.email||''), email2:String(recipient.email2||''), phone:String(recipient.phone||'') },
        items,
        payment: { cash:_n(pay.cash), check:_n(pay.check), note:_n(pay.note), credit:_n(pay.credit) },   // 현금·수표·어음·외상미수금
        amounts: { supplyAmount, taxAmount, totalAmount }, memo: String(b.memo || '')
    };
    // 발급보류(draft): 팍스빌 전송 없이 '작성중'으로 저장. 아니면 실제 발급.
    const pax = b.draft ? { mock: true, invoiceNo: 'DRAFT-' + Date.now(), issueStatus: 'draft', ntsStatus: 'not_sent' } : await _postToPaxbill('issue', payload);
    const now = _taxNow();
    const invoiceNo = pax.invoiceNo || ('TAX-' + Date.now());
    const issueStatus = pax.issueStatus || 'issued';
    const ntsStatus = pax.ntsStatus || (pax.mock ? 'nts_sent_mock' : 'nts_requested');
    const id = await new Promise((resolve, reject) => {
        db.run(`INSERT INTO tax_invoices (transactionId, seller, buyer, invoiceNo, issueStatus, ntsStatus, supplierBizNo, supplierName, recipientBizNo, recipientName, supplyAmount, taxAmount, totalAmount, invoiceType, batchMonth, payload, paxbillResponse, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [b.transactionId || null, seller, b.buyer || '', invoiceNo, issueStatus, ntsStatus, payload.supplier.bizNo, payload.supplier.name, payload.recipient.bizNo, payload.recipient.name, supplyAmount, taxAmount, totalAmount, b.invoiceType || 'commission', b.batchMonth || null, JSON.stringify(payload), JSON.stringify(pax), now, now],
            function(err){ if (err) reject(err); else resolve(this.lastID); });
    });
    return { id, invoiceNo, issueStatus, ntsStatus, seller, supplyAmount, taxAmount, totalAmount, paxbill: pax };
}
app.post('/api/tax/issue', async (req, res) => {
    if (!requireAdmin(req, res)) return;
    try { const out = await _issueOne(req.body); res.json(Object.assign({ success: true }, out)); }
    catch(e) { res.status(500).json({ error: (e && e.message) || '발행 실패' }); }
});
// Admin: 월 일괄 발행 — vendors:[{seller, recipient?, supplyAmount, taxAmount, totalAmount, item?}]
app.post('/api/tax/issue-bulk', async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const b = req.body || {};
    const vendors = Array.isArray(b.vendors) ? b.vendors : [];
    const supplier = b.supplier || {};
    if (!supplier.name || !_digits(supplier.bizNo)) return res.status(400).json({ error: '공급자(플랫폼) 상호·사업자번호를 입력하세요.' });
    if (!vendors.length) return res.status(400).json({ error: '발행 대상 업체가 없습니다.' });
    const results = [];
    for (const v of vendors) {
        try {
            const out = await _issueOne({ seller: v.seller, buyer: v.seller, supplier, recipient: v.recipient || { name: v.seller }, item: v.item || { name: (b.batchMonth || '') + ' 플랫폼 이용 수수료' }, supplyAmount: v.supplyAmount, taxAmount: v.taxAmount, totalAmount: v.totalAmount, writeDate: b.writeDate, batchMonth: b.batchMonth, invoiceType: 'commission', memo: b.memo });
            results.push({ seller: v.seller, ok: true, invoiceNo: out.invoiceNo, id: out.id });
        } catch(e) { results.push({ seller: v.seller, ok: false, error: (e && e.message) || '실패' }); }
    }
    res.json({ success: true, count: results.filter(r => r.ok).length, total: results.length, results });
});
// 세금계산서 삭제(매출 취소 등). live 발행분은 국세청 취소가 별도 필요하므로 기록만 삭제.
app.delete('/api/tax/invoices/:id', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const id = Number(req.params.id);
    db.run(`DELETE FROM tax_invoices WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});
// 여러 건 삭제
app.post('/api/tax/invoices/delete-many', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).map(Number).filter(Boolean);
    if (!ids.length) return res.status(400).json({ error: '삭제할 항목이 없습니다.' });
    db.run(`DELETE FROM tax_invoices WHERE id IN (${ids.map(() => '?').join(',')})`, ids, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});
// 상태 새로고침(국세청 전송 결과 조회 — live 시)
app.post('/api/tax/invoices/:id/refresh', async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const id = Number(req.params.id);
    db.get(`SELECT * FROM tax_invoices WHERE id = ?`, [id], async (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: '전자세금계산서를 찾을 수 없습니다.' });
        try {
            let payload = {}; try { payload = JSON.parse(row.payload || '{}'); } catch(_){}
            const pax = await _postToPaxbill('status', { id: row.id, invoiceNo: row.invoiceNo, payload });
            const now = _taxNow();
            db.run(`UPDATE tax_invoices SET issueStatus=?, ntsStatus=?, paxbillResponse=?, updated_at=? WHERE id=?`,
                [pax.issueStatus || row.issueStatus, pax.ntsStatus || row.ntsStatus, JSON.stringify(pax), now, id],
                (e2) => e2 ? res.status(500).json({ error: e2.message }) : res.json({ success: true, id, issueStatus: pax.issueStatus || row.issueStatus, ntsStatus: pax.ntsStatus || row.ntsStatus }));
        } catch(e) { res.status(500).json({ error: (e && e.message) || '상태 조회 실패' }); }
    });
});

// 🔐 방 참가자 도출 — 개인 룸 대상 전송용. 주문방(room_ord_)은 id로 파싱 불가 → chat_rooms 캐시(ORDER_ROOMS)에서 해석.
function _roomParticipants(roomId) {
    const id = String(roomId || '');
    if (id.startsWith('room_ord_')) { const m = ORDER_ROOMS.get(id); return m ? [m.buyer, m.seller].filter(Boolean) : []; }
    return id.replace('room_msg_', '').split('_').filter(Boolean);
}
// 두 참가자의 개인 룸에만 이벤트 전송(예전 io.emit 전체 브로드캐스트 → 무관한 사용자에게까지 채팅 노출되던 문제 제거). 크로스룸 알림은 개인 룸으로 유지.
function _emitToRoomUsers(roomId, event, payload) {
    const parts = _roomParticipants(roomId);
    if (parts.length) { let e = io; parts.forEach(u => { e = e.to('user:' + u); }); e.emit(event, payload); }
    else io.to(roomId).emit(event, payload);   // 비표준 roomId 폴백
}
io.on('connection', (socket) => {
    // 🔐 소켓 신원 바인딩 — 핸드셰이크 토큰으로 사용자 판정(발신자 위조 차단) + 개인 룸 자동 가입(스코프 전송 수신용)
    try {
        const t = socket.handshake && socket.handshake.auth && socket.handshake.auth.token;
        const s = t && SESSIONS.get(String(t));
        socket.data.user = s ? s.name : null;
        if (socket.data.user) socket.join('user:' + socket.data.user);
    } catch (_) { socket.data.user = null; }
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    // 🖥 원격제어 신호 중계 — 화면 프레임/입력 이벤트를 상대(수신자 개인 룸)에게만 전달.
    //    d = { to:'상대이름', roomId, kind:'frame'|'input'|'ctrl', ... }. 발신자는 토큰 신원으로 강제.
    socket.on('rc_signal', (d) => {
        if (!d || !d.to || !socket.data.user) return;
        io.to('user:' + String(d.to)).emit('rc_signal', Object.assign({}, d, { from: socket.data.user }));
    });
    socket.on('send_message', (data) => {
        if (!data || !data.roomId) return;
        if (!socket.data.user) return;   // 🔐 미인증 소켓 거부(발신자 위조 차단 — 본문 sender로 폴백하지 않음)
        // 발신자는 항상 토큰 신원으로 강제. '__system__'은 시스템 메시지(주문 카드 등)로만 허용.
        const isSystem = data.sender === '__system__';
        const sender = isSystem ? '__system__' : socket.data.user;
        const users = _roomParticipants(data.roomId);
        // senderPic(base64)은 DB 미저장(히스토리 경량화). 실시간엔 실어 보냄. 참가자 개인 룸에만 전송.
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?, ?, ?, ?, ?, ?)`, [data.roomId, sender, null, data.message, new Date().toLocaleString('ko-KR'), new Date().toISOString()], function() {
            const msgId = this.lastID;
            // 🗑 퇴장(숨김)한 참가자에겐 전달·푸시·친구재등록 안 함 → '나간 방은 완전히 끊김'(유령 미읽음 방지)
            db.all(`SELECT user FROM chat_hidden WHERE roomId = ?`, [data.roomId], (eh, hrows) => {
                const hidden = new Set((hrows || []).map(r => r.user));
                if (users.length === 2 && !hidden.has(users[0]) && !hidden.has(users[1])) {
                    db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[0], users[1]]);
                    db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[1], users[0]]);
                }
                const payload = Object.assign({}, data, { sender, id: msgId });
                if (users.length) users.forEach(u => { if (u && !(u !== sender && hidden.has(u))) { try { io.to('user:' + u).emit('receive_message', payload); } catch (_) {} } });
                else { try { io.to(data.roomId).emit('receive_message', payload); } catch (_) {} }
                try {
                    const preview = _pushPreview(String(data.message || ''));
                    if (preview && sender !== '__system__') users.forEach(u => { if (u && u !== sender && !hidden.has(u)) sendPushToUser(u, { title: sender, body: preview, data: { roomId: data.roomId } }); });
                } catch (_) {}
            });
        });
    });
    // 메시지 수정 (작성자만 — 인증 소켓이면 토큰 신원으로 판정)
    socket.on('edit_message', (data) => {
        if (!data || !data.id) return;
        if (!socket.data.user) return;   // 🔐 미인증 소켓 거부(본문 sender 폴백 금지)
        const sender = socket.data.user;
        db.run(`UPDATE chats SET message = ? WHERE id = ? AND sender = ?`, [data.message, data.id, sender], function() {
            if (this.changes) _emitToRoomUsers(data.roomId, 'message_edited', { id: data.id, roomId: data.roomId, message: data.message, sender });
        });
    });
    // 메시지 삭제 (작성자만)
    socket.on('delete_message', (data) => {
        if (!data || !data.id) return;
        if (!socket.data.user) return;   // 🔐 미인증 소켓 거부(본문 sender 폴백 금지)
        const sender = socket.data.user;
        db.run(`DELETE FROM chats WHERE id = ? AND sender = ?`, [data.id, sender], function() {
            if (this.changes) _emitToRoomUsers(data.roomId, 'message_deleted', { id: data.id, roomId: data.roomId, sender });
        });
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[EARTH MASTER VER] BOUND ON PORT ${PORT}`); });