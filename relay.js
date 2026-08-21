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

// ☁️ 앱 설치파일(APP_Setup.exe/Alpha K.apk)을 R2로 동기화 → 다운로드 전송비 무료. 크기 같으면 스킵(변경 시에만 업로드).
function _syncAppToR2() {
    if (!_r2) return;
    try {
        const { PutObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
        [{ name: 'APP_Setup.exe', ct: 'application/octet-stream' }, { name: 'Alpha K.apk', ct: 'application/vnd.android.package-archive' }].forEach(fi => {
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
        name: 'Alpha K', short_name: 'Alpha K', start_url: '/', scope: '/',
        display: 'standalone', background_color: '#0b0b0f', theme_color: '#111111',
        icons: [
            { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
            { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
            { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
        ]
    }));
});
// 📱 앱 로고·아이콘(오름 아이콘.png, 512px) — 배포(relay.js)에 인라인해 서버 파일 없이도 서빙
const APP_ICON_BUF = Buffer.from('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','base64');
app.get('/icon-192.png', (req, res) => { res.type('image/png').set('Cache-Control','public, max-age=86400').send(APP_ICON_BUF); });
app.get('/icon-512.png', (req, res) => { res.type('image/png').set('Cache-Control','public, max-age=86400').send(APP_ICON_BUF); });
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
        "  var d={}; try{ d=e.data.json(); }catch(_){ try{ d={title:'Alpha K',body:e.data&&e.data.text()}; }catch(__){ d={title:'Alpha K'}; } }\n" +
        "  var title=d.title||'Alpha K', body=d.body||'';\n" +
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
// 📦 앱 현재 버전 — 업데이트 시 4번째 자리를 올린다(예: 0.0.0.1 → 0.0.0.2). 클라가 표기·New 뱃지에 사용.
const APP_VERSION = '0.0.0.1';
app.get('/api/app/version', (req, res) => { res.json({ version: APP_VERSION }); });
// 🖥 서버 내장 설치형 PC 앱(Electron) 인스톨러 — agent/ 폴더에 두면 배포됨(git 미추적, reset 보존)
app.get('/download/APP_Setup.exe', (req, res) => {
    // ☁️ R2 설정 시 R2 공개 URL로 리다이렉트(다운로드 전송비 무료). 없으면 로컬 서빙.
    if (_r2) return res.redirect(302, _r2.publicBase + '/app/APP_Setup.exe');
    const f = path.join(RC_AGENT_DIR, 'APP_Setup.exe');
    if (!fs.existsSync(f)) return res.status(404).send('app not published yet');
    res.download(f, 'APP_Setup.exe');
});
// 📱 Android APK(사이드로드) — agent/Alpha K.apk 에 두면 배포됨. '알 수 없는 앱 허용' 후 설치.
app.get('/download/Alpha K.apk', (req, res) => {
    if (_r2) return res.redirect(302, _r2.publicBase + '/app/Alpha K.apk');
    const f = path.join(RC_AGENT_DIR, 'Alpha K.apk');
    if (!fs.existsSync(f)) return res.status(404).send('apk not published yet');
    res.type('application/vnd.android.package-archive');
    res.download(f, 'Alpha K.apk');
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
    res.json({ version: v, url: '/download/RAY_RemoteAgent.exe', exists: fs.existsSync(path.join(RC_AGENT_DIR, 'RAY_RemoteAgent.exe')), app: fs.existsSync(path.join(RC_AGENT_DIR, 'APP_Setup.exe')), appUrl: '/download/APP_Setup.exe', apk: fs.existsSync(path.join(RC_AGENT_DIR, 'Alpha K.apk')), apkUrl: '/download/Alpha K.apk' });
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

        // 🔒💰 전송 파일 잠금(선택) — 금액(price>0: 수신자가 Alpha K 잔액으로 결제해야 열림)/암호(pwHash) 설정.
        //   둘 다 미설정이면 잠금 미사용(기존 공개 전송과 동일). 실제 R2 URL은 서버에만 보관, 잠금 해제 성공 시에만 전달.
        db.run(`CREATE TABLE IF NOT EXISTS locked_files (token TEXT PRIMARY KEY, owner TEXT, fileName TEXT, url TEXT, mime TEXT, size INTEGER, price INTEGER DEFAULT 0, pwHash TEXT DEFAULT '', createdAt INTEGER)`);
        db.run(`CREATE TABLE IF NOT EXISTS locked_file_unlocks (token TEXT, userName TEXT, at INTEGER, paid INTEGER DEFAULT 0, UNIQUE(token, userName))`);

        // ☁️ [항목5] 로컬 공유폴더 R2 미러 백업(유료 옵션) — 원하는 사용자만 cloud_storage 할당량으로 결제해 사용.
        //   mirror_files: 사용자별 미러된 파일 목록(rpath=공유폴더 상대경로). mirror_prefs: 사용자별 on/off.
        db.run(`CREATE TABLE IF NOT EXISTS mirror_files (userName TEXT, rpath TEXT, key TEXT, size INTEGER DEFAULT 0, mime TEXT, mtime INTEGER, PRIMARY KEY(userName, rpath))`);
        db.run(`CREATE TABLE IF NOT EXISTS mirror_prefs (userName TEXT PRIMARY KEY, enabled INTEGER DEFAULT 0)`);

        // 🔗 [비회원 외부 공유] QR+웹링크로 Alpha K 미가입 고객에게 파일 전달 → 랜딩페이지에서 가입안내 + 공유폴더 다운로드
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
        db.run(`ALTER TABLE stores ADD COLUMN partner_clinics TEXT`, () => {});   // 🏥 기공소 거래 치과 정보(JSON, 홍보용·관리자 열람)
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
        db.run(`ALTER TABLE users ADD COLUMN license_doc TEXT`, () => {});       // (구) base64 자격증 이미지 — 미사용
        db.run(`ALTER TABLE users ADD COLUMN license_no TEXT`, () => {});        // 면허(자격) 번호 — 이미지 업로드 대체
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
        db.run(`ALTER TABLE users ADD COLUMN terms_agreed_at TEXT`, () => {});     // 📜 회원가입 동의서(이용약관) 동의 시각
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
            // 🗂 오픈 카테고리(가입 업체유형·상점 카테고리 노출 목록) — 기본: 치과 병의원 + 치과 기공소만. 관리자가 확장 가능.
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('open_categories', 'dental_clinic,dental_lab')`, () => {});
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
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_fee_rate', '2.7')`, () => {});   // 💰 수수료율 2.7%(+VAT 10%=총 2.97%)
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_pay_fee_rate', '2.7')`, () => {});
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_sw_fee', '10000')`, () => {});
            // 💰 [정산] 제5조: Alpha K 거래 수수료 총 2.7%(VAT 별도) = 카드결제 2.4% + 거래 0.3%. 결제수수료=두 율의 합, 지급액=매출−결제수수료.
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_card_fee_rate', '2.4')`, () => {});
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_txn_fee_rate', '0.3')`, () => {});
            db.run(`UPDATE settings SET value='0.3' WHERE key='tax_txn_fee_rate' AND value='0.6'`, () => {});   // 기존(3.0%) DB → 제5조 2.7% 마이그레이션
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tax_supplier', '')`, () => {});   // 공급자(플랫폼) 정보 JSON — 마지막 입력값 자동 저장
        });
        // 🔐 로그인 세션(토큰) — 자금/민감 엔드포인트의 신원을 요청 본문이 아닌 서버 세션으로 판정
        db.run(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, name TEXT, created INTEGER)`, () => {
            db.all(`SELECT token, name, created FROM sessions`, [], (e, rows) => { (rows || []).forEach(r => SESSIONS.set(r.token, { name: r.name, created: r.created })); });
        });
        // 🔔 웹 푸시 구독 저장(카톡식 알림) — endpoint 당 1행, 사용자별 다기기 허용
        db.run(`CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, userName TEXT, sub TEXT, created TEXT)`);
        // 💬 카톡식 읽음표시: 방·사용자별 마지막으로 읽은 메시지 id
        db.run(`CREATE TABLE IF NOT EXISTS chat_reads (roomId TEXT, userName TEXT, lastReadId INTEGER, PRIMARY KEY(roomId, userName))`);
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
// 🔐 단일 세션 강제(카톡식) — 새 로그인 시 이 계정의 기존 세션 모두 무효화 + 기존 소켓에 강제 로그아웃 통지.
function _enforceSingleSession(name, keepToken) {
    try {
        for (const [t, s] of SESSIONS) { if (s && s.name === name && t !== keepToken) SESSIONS.delete(t); }
        db.run(`DELETE FROM sessions WHERE name = ? AND token != ?`, [name, keepToken], () => {});
        io.to('user:' + name).emit('force_logout', { reason: '다른 기기(브라우저)에서 로그인되어 이 기기는 로그아웃되었습니다.' });
    } catch (_) {}
}
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
// 🔐 세션 유효성 핑 — 클라가 주기적으로 호출. 토큰이 무효(다른 기기 로그인으로 revoke)면 401 → 클라가 자동 로그아웃.
app.get('/api/auth/ping', (req, res) => { const me = authUser(req); if (!me) return res.status(401).json({ ok: false }); res.json({ ok: true, name: me }); });
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
                const _tk = issueToken(row.name);
                _enforceSingleSession(row.name, _tk);   // 🔐 기존 로그인 자동 로그아웃(단일 세션)
                res.json({ exists: true, user: Object.assign(stripPwd(row), { isAdmin: isAdminName(row.name) }), token: _tk, mustChangePassword: !!row.force_pwd_change, isAdmin: isAdminName(row.name) });
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
    const { name, password, realname, bank, account, phone, email, shipping_address, business_type, privacy_agreed, terms_agreed } = req.body;
    const license_no = String(req.body.license_no || '').trim();   // 면허(자격) 번호 — 이미지 업로드 대체
    // 🧾 세금계산서용 사업자 정보(선택 — 사업자는 발행 자동반영에 사용)
    const biz_no = _digits(req.body.biz_no || ''), biz_company = String(req.body.biz_company || ''), biz_ceo = String(req.body.biz_ceo || ''),
          biz_addr = String(req.body.biz_addr || ''), biz_industry = String(req.body.biz_industry || ''), biz_item = String(req.body.biz_item || ''),
          tax_email = String(req.body.tax_email || email || '');
    // 🔐 개인정보 수집·이용 동의(필수) — 미동의 시 가입 거부
    if(!privacy_agreed) return res.status(400).json({ error: '개인정보 수집·이용 동의가 필요합니다.' });
    // 📜 회원가입 동의서(서비스 이용약관) 동의(필수)
    if(!terms_agreed) return res.status(400).json({ error: '회원가입 동의서(서비스 이용약관) 동의가 필요합니다.' });
    // 🚀 의료·약무 관련 업종은 면허(자격) 번호 필수 + Admin 승인 대기
    const regulated = ['dental_lab', 'dental_clinic', 'medical', 'pharmacy', 'medical_wholesale'];
    const needsApproval = regulated.includes(business_type);
    if(needsApproval && license_no.replace(/[^0-9A-Za-z]/g,'').length < 4) return res.status(400).json({ error: '해당 업종은 면허(자격) 번호 입력이 필수입니다.' });
    const approvalStatus = needsApproval ? 'pending' : 'approved';
    const privacyAgreedAt = new Date().toISOString();   // 동의 시각 기록(보관 근거)
    const termsAgreedAt = new Date().toISOString();      // 📜 이용약관 동의 시각

    // 💳 (선택) 카드 비밀번호 4자리 — 실 PG 대비 저장만(현재 미검증). 형식 안 맞으면 저장 안 함.
    const cardPwRaw = _digits(req.body.card_pw || ''); const cardPw = /^\d{4}$/.test(cardPwRaw) ? cardPwRaw : null;
    // ⛔ 가입 축하금(10,000원) 정책 폐지 — 모든 신규 계정은 잔액 0으로 시작.
    db.run(`INSERT INTO users (name, password, realname, bank, account, balance, phone, email, shipping_address, business_type, license_no, approval_status, privacy_agreed_at, terms_agreed_at, biz_no, biz_company, biz_ceo, biz_addr, biz_industry, biz_item, tax_email, card_pw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, hashPassword(password), realname, bank, account, 0, phone || '', email || '', shipping_address || '', business_type || 'individual', license_no || null, approvalStatus, privacyAgreedAt, termsAgreedAt, biz_no, biz_company, biz_ceo, biz_addr, biz_industry, biz_item, tax_email, cardPw], (err) => {
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
    db.all(`SELECT name, realname, business_type, phone, email, license_no, license_doc, approval_status, approval_note FROM users WHERE approval_status = 'pending' ORDER BY name`, [], (err, rows) => {
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
    db.all(`SELECT name, realname, bank, account, phone, email, shipping_address, balance, business_type, license_no,
            CASE WHEN password LIKE 'scrypt$%' THEN '해시' ELSE '평문(미로그인)' END as pwState,
            CASE WHEN profilePic IS NOT NULL AND profilePic != '' THEN '있음' ELSE '없음' END as hasPic
            FROM users ORDER BY name`, [], (err, rows) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 🗂 오픈 카테고리 조회(공개) — 가입 업체유형·상점 카테고리 select 필터에 사용
app.get('/api/settings/open-categories', (req, res) => {
    db.get(`SELECT value FROM settings WHERE key='open_categories'`, [], (e, row) => {
        const v = (row && row.value) || 'dental_clinic,dental_lab';
        res.json({ categories: String(v).split(',').map(s => s.trim()).filter(Boolean) });
    });
});
// 🗂 Admin: 오픈 카테고리 설정(어떤 업체유형/카테고리를 노출할지)
app.post('/api/admin/open-categories', (req, res) => {
    if(!requireAdmin(req,res)) return;
    let cats = Array.isArray(req.body.categories) ? req.body.categories : [];
    const ALLOWED = ['individual','general','food','dental_lab','dental_clinic','medical','pharmacy','medical_wholesale','fashion','beauty','education','art','music','game','craft','construction','real_estate','auto','pet','sports','book','legal','finance','other'];
    cats = cats.map(c => String(c||'').trim()).filter(c => ALLOWED.includes(c));
    if(!cats.length) cats = ['dental_clinic','dental_lab'];   // 최소 보장(빈 목록 방지)
    db.run(`INSERT INTO settings (key, value) VALUES ('open_categories', ?) ON CONFLICT(key) DO UPDATE SET value=?`, [cats.join(','), cats.join(',')], (e) => {
        if(e) return res.status(500).json({ error: e.message });
        res.json({ ok: true, categories: cats });
    });
});

// 🏥 Admin: 회원 업종(business_type) 변경 — 잘못 가입된 업종 정정(예: 치과인데 일반 병·의원으로 가입 → 치과 병·의원)
app.post('/api/admin/user-business-type', (req, res) => {
    if(!requireAdmin(req,res)) return;
    const name = String(req.body.name || '').trim();
    const bt = String(req.body.business_type || '').trim();
    const ALLOWED = ['individual','general','food','dental_lab','dental_clinic','medical','pharmacy','medical_wholesale','fashion','beauty','education','art','music','game','craft','construction','real_estate','auto','pet','sports','book','legal','finance','other'];
    if(!name || !ALLOWED.includes(bt)) return res.status(400).json({ error: '잘못된 요청(이름/업종 확인).' });
    db.run(`UPDATE users SET business_type = ? WHERE name = ?`, [bt, name], function(e){
        if(e) return res.status(500).json({ error: e.message });
        if(this.changes === 0) return res.status(404).json({ error: '회원을 찾을 수 없습니다.' });
        res.json({ ok: true, name, business_type: bt });
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

// 🟢 현재 온라인(접속 중) 사용자 목록 — 친구 목록 로그인 상태 표시용
app.get('/api/online', (req, res) => { res.json({ users: Array.from(ONLINE.keys()) }); });

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

// ===================== 🚪 회원 탈퇴 =====================
// 계정과 개인 데이터 삭제 + 진행 중 대화방마다 '퇴장' 시스템 메시지(=상대가 나갔을 때와 동일) 전송.
// 재무 원장(transactions/transfers/deposits/withdrawals/refund_requests)은 기록 보존.
app.post('/api/account/withdraw', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    if (isAdminName(me)) return res.status(403).json({ error: '관리자 계정은 탈퇴할 수 없습니다. 먼저 관리자 권한을 다른 계정으로 이전하세요.' });
    // 💰 잔액이 남아 있으면 탈퇴 불가 — 먼저 출금 완료해야 함(잔액 소실 방지)
    db.get(`SELECT balance FROM users WHERE name = ?`, [me], (eb, urow) => {
        if (eb || !urow) return res.status(404).json({ error: '계정을 찾을 수 없습니다.' });
        const bal = Number(urow.balance) || 0;
        if (bal > 0) return res.status(400).json({ error: '남은 잔액 ' + bal.toLocaleString() + '원을 먼저 출금(정산)한 뒤 탈퇴할 수 있습니다.', balance: bal, needWithdrawFunds: true });
        _doWithdrawAccount(me, res);
    });
});
function _doWithdrawAccount(me, res) {
    const LEAVE_MSG = '🚪 상대방이 대화방을 퇴장하셨습니다.';
    const now = new Date().toLocaleString('ko-KR'); const iso = new Date().toISOString();
    // 1) 내가 속한 활성 대화방 수집(개인방 room_msg_ + 주문방 chat_rooms)
    db.all(`SELECT DISTINCT roomId FROM chats WHERE roomId LIKE 'room_msg_%'`, [], (e1, drows) => {
        const dmRooms = (drows || []).map(r => r.roomId).filter(rid => _roomParticipants(rid).includes(me));
        db.all(`SELECT roomId FROM chat_rooms WHERE buyer = ? OR seller = ?`, [me, me], (e2, orows) => {
            const rooms = Array.from(new Set(dmRooms.concat((orows || []).map(r => r.roomId)).filter(Boolean)));
            // 각 방에 이미 상대가 나가지 않았다면 퇴장 안내 + 내 숨김 기록
            db.all(`SELECT roomId, user FROM chat_hidden`, [], (e3, hrows) => {
                const hiddenBy = {}; (hrows || []).forEach(h => { (hiddenBy[h.roomId] = hiddenBy[h.roomId] || new Set()).add(h.user); });
                rooms.forEach(rid => {
                    const others = _roomParticipants(rid).filter(p => p && p !== me);
                    const someoneStays = others.some(o => !(hiddenBy[rid] && hiddenBy[rid].has(o)));
                    db.run(`INSERT INTO chat_hidden (user, roomId, hidden_at) VALUES (?, ?, ?)`, [me, rid, iso], () => {});
                    if (someoneStays) {
                        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?, '__system__', NULL, ?, ?, ?)`, [rid, LEAVE_MSG, now, iso], function () {
                            try { _emitToRoomUsers(rid, 'receive_message', { roomId: rid, sender: '__system__', message: LEAVE_MSG, id: this.lastID, date: now }); } catch (_) {}
                        });
                    }
                });
                // 2) R2 미러 사본 삭제(용량 회수)
                db.all(`SELECT key FROM mirror_files WHERE userName = ?`, [me], (em, mrows) => {
                    const keys = (mrows || []).map(r => r.key).filter(Boolean);
                    if (_r2 && keys.length) { try { const { DeleteObjectsCommand } = require('@aws-sdk/client-s3'); for (let i = 0; i < keys.length; i += 1000) _r2.client.send(new DeleteObjectsCommand({ Bucket: _r2.bucket, Delete: { Objects: keys.slice(i, i + 1000).map(k => ({ Key: k })) } })).catch(() => {}); } catch (_) {} }
                    // 3) 계정 + 개인 데이터 삭제(재무 원장은 보존)
                    db.serialize(() => {
                        db.run(`DELETE FROM users WHERE name = ?`, [me]);
                        db.run(`DELETE FROM friends WHERE userName = ? OR friendName = ?`, [me, me]);
                        db.run(`DELETE FROM push_subs WHERE userName = ?`, [me]);
                        db.run(`DELETE FROM devices WHERE userName = ?`, [me]);
                        db.run(`DELETE FROM mirror_files WHERE userName = ?`, [me]);
                        db.run(`DELETE FROM mirror_prefs WHERE userName = ?`, [me]);
                        db.run(`DELETE FROM guest_shares WHERE owner = ?`, [me]);
                        db.run(`DELETE FROM locked_files WHERE owner = ?`, [me]);
                        db.run(`DELETE FROM favorite_stores WHERE userName = ?`, [me]);
                        db.run(`DELETE FROM products WHERE seller = ?`, [me]);
                        db.run(`DELETE FROM stores WHERE owner = ?`, [me]);
                        // 4) 세션 폐기(재로그인 불가)
                        db.all(`SELECT token FROM sessions WHERE name = ?`, [me], (es, srows) => {
                            (srows || []).forEach(s => SESSIONS.delete(String(s.token)));
                            db.run(`DELETE FROM sessions WHERE name = ?`, [me], () => {
                                res.json({ ok: true, roomsNotified: rooms.length });
                            });
                        });
                    });
                });
            });
        });
    });
}

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

// ☁️ 클라우드 저장 용량 (Alpha K 지갑 결제) — 100MB 무료, 500GB당 3만원(= GB당 60원)
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
// Alpha K 미가입 고객에게 파일 전달: 회원이 링크 생성 → 메일/메신저로 QR+링크 전송 → 고객이 랜딩페이지에서 가입안내 + 공유폴더 다운로드.
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
<title>Alpha K 파일 받기</title><link rel="icon" href="/icon-192.png">
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
 <div class="brand"><span class="dot">A</span> Alpha K</div>
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
       +'<a class="btn p" href="'+claimUrl+'">📥 Alpha K에서 받기 (공유폴더 자동저장)</a>'
       +'<a class="btn o" href="'+dl+'">⬇️ 로그인 없이 바로 다운로드</a>'
       +'<div class="join"><h3>🌍 Alpha K로 받으면?</h3><p>가입/로그인하면 이 파일이 보낸 분과의 <b>채팅방으로 전달</b>되어 지정한 <b>공유폴더에 자동 저장</b>됩니다. 이후 채팅·대용량 전송·백업까지 그대로 쓸 수 있어요. "바로 다운로드"는 가입 없이 파일만 내려받습니다.</p></div>';
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
        // 🏥 거래 치과 정보(홍보용) — 화이트리스트 필드만 정제 저장
        let clinics = null;
        if (isLab && Array.isArray(req.body.clinics) && req.body.clinics.length) {
            clinics = req.body.clinics.slice(0, 500).map(c => ({
                name: String((c && c.name) || '').slice(0, 100), ceo: String((c && c.ceo) || '').slice(0, 60),
                phone: String((c && c.phone) || '').slice(0, 40), addr: String((c && c.addr) || '').slice(0, 200),
                email: String((c && c.email) || '').slice(0, 120)
            })).filter(c => c.name || c.ceo || c.phone || c.addr);
        }
        db.run(`INSERT INTO stores (id, name, owner, logo, status, background, description, category, bizType, bizNo, rx_items, partner_clinics) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
            [storeId, req.body.name, req.body.owner, req.body.logo, req.body.background || '', req.body.description || '', category, bizType, bizNo, rxItems ? JSON.stringify(rxItems) : null, clinics ? JSON.stringify(clinics) : null],
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

// 🏥 상점 소유자(또는 관리자): 거래 치과 정보 조회
app.get('/api/store/:id/clinics', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.get(`SELECT owner, partner_clinics FROM stores WHERE id = ?`, [req.params.id], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '상점이 존재하지 않습니다.' });
        if (row.owner !== me && !isAdminName(me)) return res.status(403).json({ error: '본인 상점만 조회할 수 있습니다.' });
        let clinics = []; try { clinics = JSON.parse(row.partner_clinics || '[]') || []; } catch (_) {}
        res.json({ clinics });
    });
});
// 🏥 상점 소유자(또는 관리자): 거래 치과 정보 저장(전체 교체)
app.post('/api/store/:id/clinics', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    db.get(`SELECT owner FROM stores WHERE id = ?`, [req.params.id], (e, row) => {
        if (e || !row) return res.status(404).json({ error: '상점이 존재하지 않습니다.' });
        if (row.owner !== me && !isAdminName(me)) return res.status(403).json({ error: '본인 상점만 수정할 수 있습니다.' });
        let clinics = [];
        if (Array.isArray(req.body.clinics)) clinics = req.body.clinics.slice(0, 500).map(c => ({
            name: String((c && c.name) || '').slice(0, 100), ceo: String((c && c.ceo) || '').slice(0, 60),
            phone: String((c && c.phone) || '').slice(0, 40), addr: String((c && c.addr) || '').slice(0, 200),
            email: String((c && c.email) || '').slice(0, 120)
        })).filter(c => c.name || c.ceo || c.phone || c.addr);
        db.run(`UPDATE stores SET partner_clinics = ? WHERE id = ?`, [clinics.length ? JSON.stringify(clinics) : null, req.params.id], (ue) => {
            if (ue) return res.status(500).json({ error: ue.message });
            res.json({ ok: true, count: clinics.length });
        });
    });
});

// 🏥 [관리자] 기공소 상점의 거래 치과 정보 열람(홍보용). 관리자 전용.
app.get('/api/admin/partner-clinics', (req, res) => {
    if (!requireAdmin(req, res)) return;
    db.all(`SELECT id, name AS storeName, owner, partner_clinics FROM stores WHERE category='dental_lab' AND partner_clinics IS NOT NULL AND partner_clinics != '' ORDER BY name`, [], (e, rows) => {
        if (e) return res.status(500).json({ error: e.message });
        const out = []; let total = 0;
        (rows || []).forEach(r => { let clinics = []; try { clinics = JSON.parse(r.partner_clinics) || []; } catch (_) {} if (clinics.length) { out.push({ storeId: r.id, storeName: r.storeName, owner: r.owner, clinics }); total += clinics.length; } });
        res.json({ stores: out, totalStores: out.length, totalClinics: total });
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
                const orderId = this.lastID;
                // 🔔 판매자에게 새 주문 푸시(앱이 꺼져 있어도 수신) — 주문 대화방으로 딥링크
                try { sendPushToUser(seller, { title: '🛒 새 주문 요청', body: (buyer || '고객') + ' 님이 주문서를 보냈습니다.', data: { roomId: _orderRoomId(orderId) } }); } catch (_) {}
                res.json({ success: true, orderId, payMethod: method, approvalNo: pgApproval, amount });
            });
    });
});

// 💬 [채팅 상태알림] 주문 상태가 바뀔 때 구매자·판매자 채팅방에 시스템 메시지 기록 + order_status 이벤트(카드 갱신용) 방출.
function _orderRoomId(orderId) { return 'room_ord_' + orderId; }   // 💬 주문별 고유 대화방 id
function _notifyOrderStatus(buyer, seller, orderId, status, msg, actor) {
    try {
        const roomId = _orderRoomId(orderId);
        _setOrderRoom(roomId, buyer, seller);   // 참가자 캐시 보강(소켓 전송용)
        if (msg) {
            const date = new Date().toLocaleString('ko-KR');
            db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date, created_at) VALUES (?, '__system__', NULL, ?, ?, ?)`, [roomId, msg, date, new Date().toISOString()], function() {
                try { _emitToRoomUsers(roomId, 'receive_message', { roomId, sender: '__system__', message: msg, id: this.lastID, date }); } catch (_) {}
            });
            // 🔔 주문 상태 변경 푸시(앱 꺼져 있어도 수신) — 행위자(actor) 제외한 상대에게
            try {
                const clean = String(msg).replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().slice(0, 70);
                [buyer, seller].filter(u => u && u !== actor).forEach(u => sendPushToUser(u, { title: '🛒 주문 알림', body: clean, data: { roomId } }));
            } catch (_) {}
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
                const msg = status === 'delivered' ? '📦 [상품서비스 제공 완료] 상품서비스가 제공되었습니다. 확인 후 완료(구매확정)를 눌러주세요. (제4조: 5영업일 경과 시 자동 완결 · 완결 후 3영업일 이내 수수료 2.7% 제외 금액 지급)'
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
                        try { sendPushToUser(ord.seller, { title: `🔁 ${label} 요청`, body: (ord.buyer || '고객') + ' 님이 재작업을 요청했습니다.', data: { roomId: _orderRoomId(newId) } }); } catch (_) {}
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

// 📅 n영업일 전 시각(ISO) — 주말(토·일) 제외하고 하루씩 되돌아 카운트. 제4조 마(5영업일) 자동완결 기준.
function _businessDaysAgoISO(n) {
    const d = new Date(); let cnt = 0;
    while (cnt < n) { d.setDate(d.getDate() - 1); const w = d.getDay(); if (w !== 0 && w !== 6) cnt++; }
    return d.toISOString();
}
// 📅 기준일(ISO) + n영업일 후 날짜(ISO). 주말 제외. 정산예정일 계산용(제4조 바 3영업일 / 마 5영업일).
function _addBusinessDaysISO(baseISO, n) {
    if (!baseISO) return null;
    const d = new Date(baseISO); if (isNaN(d.getTime())) return null; let cnt = 0;
    while (cnt < n) { d.setDate(d.getDate() + 1); const w = d.getDay(); if (w !== 0 && w !== 6) cnt++; }
    return d.toISOString();
}
// 💰 정산예정일 = min(구매확정일+3영업일, 배송완료일+5영업일). 선도래일 반환(ISO). 둘 다 없으면 null.
function _settleDueISO(confirmedAt, deliveredAt) {
    const a = confirmedAt ? _addBusinessDaysISO(confirmedAt, 3) : null;
    const b = deliveredAt ? _addBusinessDaysISO(deliveredAt, 5) : null;
    if (a && b) return (a <= b) ? a : b;
    return a || b || null;
}
// 💰 [에스크로] 제4조 마: 배송완료(delivered) 후 5영업일 경과 에스크로 주문을 자동 confirmed 처리(구매자 미확정 시).
//  자금 이동 없음(정산 대기로 전환만). 1시간마다 실행 + 부팅 30초 후 1회.
function _autoConfirmSweep() {
    try {
        const cutoff = _businessDaysAgoISO(5);   // 제4조 마: 5영업일 경과
        db.all(`SELECT id, buyer, seller, delivered_at FROM product_orders WHERE status='delivered' AND escrow_held > 0 AND settled = 0 AND delivered_at IS NOT NULL AND delivered_at <= ?`, [cutoff], (e, rows) => {
            if (e || !rows || !rows.length) return;
            const now = new Date(); const month = _kstMonth();   // 정산 귀속월(KST 기준)
            rows.forEach(r => db.run(`UPDATE product_orders SET status='confirmed', confirmed_at = ?, settle_month = ? WHERE id = ?`, [now.toISOString(), month, r.id], () => { _notifyOrderStatus(r.buyer, r.seller, r.id, 'confirmed', '🎉 [자동 완결] 상품서비스 제공 후 5영업일 경과로 자동 완결(구매확정) 처리되었습니다. 완결 후 3영업일 이내에 수수료(2.7%)를 제외한 금액이 판매자에게 지급됩니다. 이 대화방은 종료됩니다.'); _closeOrderRoom(r.id, r.buyer, r.seller); }));
            console.log(`[에스크로] 자동 완결(구매확정) ${rows.length}건 (5영업일 경과)`);
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
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, rawDate, date) VALUES (?, ?, ?, ?, ?, ?)`, [issuer, 'Alpha K(Root)', '보안 수표 발행', amount, rawDate, date]);
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
                db.run(`INSERT INTO transactions (buyer, seller, productName, amount, rawDate, date) VALUES (?, ?, ?, ?, ?, ?)`, ['Alpha K(Root)', redeemer, '보안 수표 환원 충전', row.amount, rawDate, date]);
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
        dps.forEach(d => history.push({ type: `입금 신청 (${d.status})`, date: d.date, rawDate: d.rawDate || d.date, amount: d.amount, seller: 'Alpha K(Root)' }));
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
// 정산 변수 조회 — 수수료율 2.7% + VAT 10%(수수료의 10%=0.27%), 총 부담 2.97%.
function _taxConfig(cb){
    db.all(`SELECT key,value FROM settings WHERE key IN ('tax_fee_rate','tax_vat_rate','tax_card_fee_rate','tax_txn_fee_rate')`, [], (e, rows) => {
        const m = {}; (rows||[]).forEach(r => m[r.key] = r.value);
        let feeRate = parseFloat(m.tax_fee_rate);
        if (isNaN(feeRate)) { const c = parseFloat(m.tax_card_fee_rate), t = parseFloat(m.tax_txn_fee_rate); feeRate = (isNaN(c)?0:c) + (isNaN(t)?0:t); if (!feeRate) feeRate = 2.7; }   // 하위호환
        let vatRate = parseFloat(m.tax_vat_rate); if (isNaN(vatRate)) vatRate = 10;
        cb({ feeRate, vatRate, payFeeRate: feeRate * (1 + vatRate/100),
             cardFeeRate: feeRate, txnFeeRate: 0 });   // 하위호환 필드
    });
}
// 매출 → 정산 내역. 수수료(공급가)=매출×2.7%(원단위 버림), VAT=수수료×10%(원단위 버림), 총수수료=수수료+VAT(≈2.97%), 지급액=매출−총수수료.
//  예) 매출 10,000 → 수수료 270, VAT 27, 총 297, 지급 9,703.
function _settleCalc(salesTotal, cfg){
    salesTotal = _n(salesTotal);
    let feeRate = parseFloat(cfg && cfg.feeRate); if (isNaN(feeRate)) feeRate = 2.7;
    let vatRate = parseFloat(cfg && cfg.vatRate); if (isNaN(vatRate)) vatRate = 10;
    const fee = Math.floor(salesTotal * feeRate / 100);   // 수수료(공급가) — 원단위 이하 버림
    const vat = Math.floor(fee * vatRate / 100);          // VAT — 원단위 이하 버림
    const payFee = fee + vat;                             // 총 수수료(=Admin 수입, ≈2.97%)
    const payout = salesTotal - payFee;                   // 상점 지급액
    return { salesTotal, fee, vat, payFee, feeRate, vatRate, payout,
        // 하위호환(세금계산서: 공급가액=fee, 세액=vat)
        cardFee: fee, txnFee: vat, commissionTotal: fee, feeSubtotal: fee, vatOnFees: vat, swFee: 0 };
}
const _salesWhere = `t.productId IS NOT NULL AND IFNULL(t.refunded,0)=0 AND t.purchaseType IS NOT NULL AND t.purchaseType NOT IN ('refund','signup_bonus')`;

// 팍스빌 연동 모드(live/mock)
app.get('/api/tax/config/status', (req, res) => { res.json(_paxbillStatus()); });
// 정산 변수 조회/변경(Admin)
app.get('/api/tax/config', (req, res) => { _taxConfig(cfg => res.json(cfg)); });
app.post('/api/tax/config', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const map = { tax_fee_rate: req.body.feeRate, tax_vat_rate: req.body.vatRate };
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
                    MAX(o.confirmed_at) lastConfirmedAt, MIN(o.confirmed_at) firstConfirmedAt, MIN(o.delivered_at) firstDeliveredAt,
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
            const vendors = (rows || []).map(r => {
                // 정산예정일 = min(구매확정일+3영업일, 배송완료일+5영업일). 상점 집계라 가장 임박한 확정건 기준.
                const settleDue = _settleDueISO(r.firstConfirmedAt, r.firstDeliveredAt);
                return Object.assign({
                    seller: r.seller, count: r.cnt,
                    bizName: (r.su_company && r.su_company.trim()) || (r.sellerRealname && r.sellerRealname.trim()) || (r.brands ? String(r.brands).split(',')[0] : '') || r.seller,
                    bizNo: r.su_bizno || (r.bizNos ? String(r.bizNos).split(',')[0] : ''),
                    bizCeo: r.su_ceo || r.sellerRealname || '', bizAddr: r.su_addr || '', bizIndustry: r.su_industry || '', bizItem: r.su_item || '', taxEmail: r.su_taxemail || r.su_email || '',
                    storeIds: r.storeIds || '', brands: r.brands || '',
                    confirmedAt: r.lastConfirmedAt || '', firstConfirmedAt: r.firstConfirmedAt || '', firstDeliveredAt: r.firstDeliveredAt || '',
                    settleDueAt: settleDue || '', settleDuePassed: settleDue ? (settleDue <= new Date().toISOString()) : false
                }, _settleCalc(r.salesTotal, cfg));
            });
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
    const from = String(req.query.from || '').slice(0, 10);   // 정산완료일 기간(YYYY-MM-DD)
    const to = String(req.query.to || '').slice(0, 10);
    _taxConfig((cfg) => {
        let where = `o.settled=1 AND o.escrow_held>0`; const params = [];
        // 기간(from/to)이 있으면 정산완료일 기준, 없으면 월(settle_month) 기준
        if (from || to) {
            if (from) { where += ` AND date(o.settled_at) >= date(?)`; params.push(from); }
            if (to) { where += ` AND date(o.settled_at) <= date(?)`; params.push(to); }
        } else if (month) { where += ` AND o.settle_month=?`; params.push(month); }
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
// 🟢 온라인 사용자 추적(name → 접속 소켓 수)
const ONLINE = new Map();
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
    // 🟢 접속 상태(presence) — 사용자별 소켓 수 카운트. 0→1이면 온라인, 1→0이면 오프라인 브로드캐스트.
    try {
        const u = socket.data.user;
        if (u) {
            const n = (ONLINE.get(u) || 0) + 1; ONLINE.set(u, n);
            if (n === 1) io.emit('presence', { user: u, online: true });
        }
    } catch (_) {}
    socket.on('disconnect', () => {
        try {
            const u = socket.data.user; if (!u) return;
            const n = (ONLINE.get(u) || 1) - 1;
            if (n <= 0) { ONLINE.delete(u); io.emit('presence', { user: u, online: false }); }
            else ONLINE.set(u, n);
        } catch (_) {}
    });
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    // 💬 읽음 처리(카톡식 '1' 제거) — 방 진입/수신 시 호출. 내 lastReadId 갱신 + 상대에게 통지 + 상대의 lastRead 회신.
    socket.on('read_room', (d) => {
        const me = socket.data.user; if (!me || !d || !d.roomId) return;
        const roomId = String(d.roomId);
        db.get(`SELECT MAX(id) mx FROM chats WHERE roomId = ?`, [roomId], (e, r) => {
            const mx = (r && r.mx) || 0;
            db.run(`INSERT INTO chat_reads (roomId, userName, lastReadId) VALUES (?, ?, ?) ON CONFLICT(roomId, userName) DO UPDATE SET lastReadId = MAX(lastReadId, excluded.lastReadId)`, [roomId, me, mx], () => {
                const others = _roomParticipants(roomId).filter(u => u && u !== me);
                others.forEach(o => {
                    try { io.to('user:' + o).emit('room_read', { roomId, reader: me, lastReadId: mx }); } catch (_) {}   // 상대 화면의 내 '1' 제거용
                    db.get(`SELECT lastReadId FROM chat_reads WHERE roomId = ? AND userName = ?`, [roomId, o], (e2, rr) => {   // 내가 볼 상대 읽음 상태 회신
                        try { io.to('user:' + me).emit('room_read', { roomId, reader: o, lastReadId: (rr && rr.lastReadId) || 0 }); } catch (_) {}
                    });
                });
            });
        });
    });
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