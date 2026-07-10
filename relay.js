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
        // 🚀 [v6] order_orders 컬럼 추가 (구버전 DB 호환)
        db.run(`ALTER TABLE product_orders ADD COLUMN pdf_filled_data TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN buyer_info TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN status TEXT DEFAULT 'approved'`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN tracking TEXT`, () => {});   // 🚚 배송 송장번호(선택)
        db.run(`ALTER TABLE product_orders ADD COLUMN courier TEXT`, () => {});    // 🚚 택배사 코드
        db.run(`ALTER TABLE product_orders ADD COLUMN amount INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE transactions ADD COLUMN refunded INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN business_type TEXT DEFAULT 'individual'`, () => {});
        // 🚀 [v8+] 자격증 + 승인 워크플로우
        db.run(`ALTER TABLE users ADD COLUMN license_doc TEXT`, () => {});       // base64 자격증 이미지
        db.run(`ALTER TABLE users ADD COLUMN approval_status TEXT DEFAULT 'approved'`, () => {});  // approved | pending | rejected
        db.run(`ALTER TABLE users ADD COLUMN approval_note TEXT`, () => {});      // 승인/거절 사유
        db.run(`ALTER TABLE users ADD COLUMN shipping_address TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp_expiry INTEGER`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp_used INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN privacy_agreed_at TEXT`, () => {});   // 🔐 개인정보 수집·이용 동의 시각
        db.run(`ALTER TABLE users ADD COLUMN force_pwd_change INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE transfers ADD COLUMN rawDate TEXT`, () => {});
        db.run(`ALTER TABLE deposits ADD COLUMN rawDate TEXT`, () => {});
        db.run(`ALTER TABLE withdrawals ADD COLUMN rawDate TEXT`, () => {});
        // 🚀 products: 패키지 메타 (대표 파일 + PDF + 추가 파일 묶음 JSON)
        db.run(`ALTER TABLE products ADD COLUMN package_data TEXT`, () => {});
        db.run(`ALTER TABLE products ADD COLUMN is_package INTEGER DEFAULT 0`, () => {});

        // 🚀 [v8+] 전역 설정 (Admin 권한 비밀번호 등) — 초기값 'mars'
        db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`, () => {
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_password', 'mars')`, () => {});
            // 🔐 관리자 계정 허용목록(쉼표구분 로그인ID) — 예전 공유 비밀번호 'mars' 백도어를 대체하는 신원 기반 권한. 기본: 소유자 계정.
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_users', 'hi840508')`, () => {});
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
        });
        // 🔐 로그인 세션(토큰) — 자금/민감 엔드포인트의 신원을 요청 본문이 아닌 서버 세션으로 판정
        db.run(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, name TEXT, created INTEGER)`, () => {
            db.all(`SELECT token, name FROM sessions`, [], (e, rows) => { (rows || []).forEach(r => SESSIONS.set(r.token, { name: r.name })); });
        });
    });
}
initTables();
setTimeout(loadAdminUsers, 500);   // 부팅 후 admin_users 설정 반영(기본 '이재준')

// 🔐 세션 토큰: 로그인 시 발급, 이후 x-auth-token 헤더로 서버가 사용자 판정(본문 신원 위조 차단)
const SESSIONS = new Map();   // token -> { name }
function issueToken(name) {
    const token = crypto.randomBytes(24).toString('hex');
    SESSIONS.set(token, { name });
    db.run(`INSERT INTO sessions (token, name, created) VALUES (?, ?, ?)`, [token, name, Date.now()], () => {});
    return token;
}
function revokeToken(token) { if (token) { SESSIONS.delete(String(token)); db.run(`DELETE FROM sessions WHERE token = ?`, [String(token)], () => {}); } }
function authUser(req) {
    const t = req.headers['x-auth-token'] || (req.body && req.body._token) || (req.query && req.query._token);
    if (!t) return null;
    const s = SESSIONS.get(String(t));
    return s ? s.name : null;
}
// 자금/민감 엔드포인트 가드: 로그인 필수 + acting user 반환. bodyNameField가 있으면 본문 신원과 토큰 신원 불일치 시 거부.
function requireUser(req, res) {
    const me = authUser(req);
    if (!me) { res.status(401).json({ error: '로그인이 필요합니다. (세션 만료 시 다시 로그인)' }); return null; }
    return me;
}

// 🔐 관리자 신원(세션 토큰 기반). ⛔ 예전 'mars' 공유 비밀번호 백도어 폐지 — settings.admin_users(쉼표구분, 기본 '이재준')에 속한 로그인 사용자만 관리자.
let ADMIN_USERS = new Set(['hi840508']);
function loadAdminUsers() {
    db.get(`SELECT value FROM settings WHERE key='admin_users'`, [], (e, row) => {
        if (row && row.value) ADMIN_USERS = new Set(String(row.value).split(',').map(s => s.trim()).filter(Boolean));
    });
}
function isAdminName(name) { return !!name && ADMIN_USERS.has(name); }
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

// Admin 권한 비밀번호 확인 (활성화용)
app.post('/api/admin/verify-password', (req, res) => {
    getAdminPassword((pw) => {
        res.json({ ok: (req.body.password || '') === pw });
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
    const { fileId, k, expiry, creator, title } = req.body || {};
    if (!fileId || !k) return res.status(400).json({ error: 'fileId/k \ud544\uc694' });
    db.get(`SELECT boundUser, firstOpenedAt FROM viewer_files WHERE fileId = ?`, [fileId], (e, prev) => {
        db.run(`INSERT OR REPLACE INTO viewer_files (fileId,k,expiry,creator,title,boundUser,firstOpenedAt,createdAt) VALUES (?,?,?,?,?,?,?,?)`,
            [fileId, String(k), Number(expiry) || 0, creator || '', title || '', (prev && prev.boundUser) || null, (prev && prev.firstOpenedAt) || null, Date.now()],
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
    db.get(`SELECT * FROM users WHERE name = ?`, [req.body.name], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            if (verifyPassword(req.body.password, row.password)) {
                upgradePasswordIfLegacy(row.name, row.password, req.body.password);
                res.json({ exists: true, user: Object.assign(stripPwd(row), { isAdmin: isAdminName(row.name) }), token: issueToken(row.name), mustChangePassword: !!row.force_pwd_change, isAdmin: isAdminName(row.name) });
            }
            else res.status(401).json({ exists: true, error: "비밀번호가 불일치합니다." });
        } else res.json({ exists: false });
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
    // 🔐 개인정보 수집·이용 동의(필수) — 미동의 시 가입 거부
    if(!privacy_agreed) return res.status(400).json({ error: '개인정보 수집·이용 동의가 필요합니다.' });
    // 🚀 [v8+] 의료·약무 관련 업종은 자격증 필수 + Admin 승인 대기
    const regulated = ['dental_lab', 'medical', 'pharmacy', 'medical_wholesale'];
    const needsApproval = regulated.includes(business_type);
    if(needsApproval && !license_doc) return res.status(400).json({ error: '해당 업종은 자격증 업로드가 필수입니다.' });
    const approvalStatus = needsApproval ? 'pending' : 'approved';
    const privacyAgreedAt = new Date().toISOString();   // 동의 시각 기록(보관 근거)

    db.run(`INSERT INTO users (name, password, realname, bank, account, balance, phone, email, shipping_address, business_type, license_doc, approval_status, privacy_agreed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, hashPassword(password), realname, bank, account, needsApproval ? 0 : 10000, phone || '', email || '', shipping_address || '', business_type || 'individual', license_doc || null, approvalStatus, privacyAgreedAt], (err) => {
        if (err) return res.status(500).json({ error: "회원 ID 중복 또는 생성 에러" });
        // 승인 대기는 보너스 X. 자동 승인 회원만 10,000원 정산 한도 축하금
        if(!needsApproval) {
            const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                ['Earth(Root)', name, '신규 가입 정산 한도 축하금', 10000, 'signup_bonus', rawDate, date]);
        }
        res.json({
            name, realname, bank, account,
            phone: phone || '', email: email || '', shipping_address: shipping_address || '',
            business_type: business_type || 'individual',
            approval_status: approvalStatus,
            balance: needsApproval ? 0 : 10000,
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
        // 승인 시 가입 축하금 지급 (지급 이력이 없을 때만)
        if(decision === 'approved') {
            db.get(`SELECT id FROM transactions WHERE seller = ? AND purchaseType = 'signup_bonus'`, [name], (gerr, existing) => {
                if(!existing) {
                    const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
                    db.run(`INSERT INTO transactions (buyer, seller, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        ['Earth(Root)', name, '신규 가입 정산 한도 축하금', 10000, 'signup_bonus', rawDate, date]);
                    db.run(`UPDATE users SET balance = COALESCE(balance, 0) + 10000 WHERE name = ?`, [name]);
                }
                res.json({ success: true, decision });
            });
        } else {
            res.json({ success: true, decision });
        }
    });
});

app.post('/api/user/update', (req, res) => {
    const me = requireUser(req, res); if (!me) return;
    // 🔐 본인 계정만 수정 가능(예전: 무인증 → 타인 계정 탈취 가능)
    if (req.body.name && req.body.name !== me) return res.status(403).json({ error: '본인 계정만 수정할 수 있습니다.' });
    const target = me;
    // 비밀번호는 새로 입력했을 때만 변경(빈 값이면 유지) + 해시 저장
    const pw = req.body.password;
    if (pw && String(pw).length > 0) {
        db.run(`UPDATE users SET password = ?, realname = ?, bank = ?, account = ?, profilePic = ?, phone = ?, email = ?, shipping_address = ? WHERE name = ?`,
            [hashPassword(pw), req.body.realname, req.body.bank, req.body.account, req.body.profilePic, req.body.phone || '', req.body.email || '', req.body.shipping_address || '', target],
            () => res.json({ success: true }));
    } else {
        db.run(`UPDATE users SET realname = ?, bank = ?, account = ?, profilePic = ?, phone = ?, email = ?, shipping_address = ? WHERE name = ?`,
            [req.body.realname, req.body.bank, req.body.account, req.body.profilePic, req.body.phone || '', req.body.email || '', req.body.shipping_address || '', target],
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
app.get('/api/users/:name', (req, res) => { db.get(`SELECT name, balance, profilePic, phone, email, shipping_address, realname FROM users WHERE name = ?`, [req.params.name], (err, row) => res.json(row || { balance: 0 })); });

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
    const { name, otp } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if(!row) return res.status(404).json({ error: "ID를 찾을 수 없습니다." });
        if(!row.reset_otp) return res.status(400).json({ error: "발급된 OTP가 없습니다. 먼저 OTP를 요청해 주세요." });
        if(row.reset_otp_used) return res.status(400).json({ error: "이미 사용된 OTP입니다." });
        if(Date.now() > Number(row.reset_otp_expiry || 0)) return res.status(400).json({ error: "OTP가 만료되었습니다. 다시 요청해 주세요." });
        if(row.reset_otp !== String(otp).trim()) return res.status(401).json({ error: "OTP가 일치하지 않습니다." });
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
    const { userName, friendName } = req.body;
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
app.get('/api/friends/:userName', (req, res) => { db.all(`SELECT u.name, u.profilePic FROM friends f JOIN users u ON f.friendName = u.name WHERE f.userName = ?`, [req.params.userName], (err, rows) => res.json(rows || [])); });

app.get('/api/chat/active-rooms/:name', (req, res) => {
    const name = req.params.name;
    // 🚀 INSTR로 안전하게 참여자 매칭. roomId 형식 = room_msg_userA_userB (정렬됨)
    // '_' + roomId + '_' 안에 '_userName_' 부분문자열이 있으면 참여 → 양쪽 모두 정확히 매칭
    const query = `
        SELECT roomId, sender, message, date, senderPic
        FROM chats
        WHERE id IN (SELECT MAX(id) FROM chats GROUP BY roomId)
          AND INSTR('_' || roomId || '_', '_' || ? || '_') > 0
        ORDER BY id DESC`;
    db.all(query, [name], (err, rows) => {
        if(err) { console.error('active-rooms query error:', err); return res.json([]); }
        if(!rows || rows.length === 0) return res.json([]);
        // 각 방의 상대방 프로필 사진을 별도 조회 (정확한 partnerName으로)
        const tasks = rows.map(r => new Promise(resolve => {
            // roomId에서 'room_msg_' 제거 후 사용자명 분리. 본인이 아닌 쪽이 상대방.
            const stripped = r.roomId.replace('room_msg_', '');
            const parts = stripped.split('_');
            const partnerName = parts.filter(n => n !== name)[0] || '이재준';
            db.get(`SELECT profilePic FROM users WHERE name = ?`, [partnerName], (e, u) => {
                resolve({
                    roomId: r.roomId,
                    partnerName,
                    lastMsg: r.message,
                    lastDate: r.date,
                    partnerPic: u ? u.profilePic : null
                });
            });
        }));
        Promise.all(tasks).then(result => res.json(result)).catch(() => res.json([]));
    });
});

app.post('/api/deposit/request', (req, res) => { const rawDate = new Date().toISOString(); db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date, rawDate) VALUES (?, ?, ?, '대기', ?, ?)`, [req.body.userName, req.body.senderName, Number(req.body.amount)||0, new Date().toLocaleString('ko-KR'), rawDate], () => { res.json({ success: true }); }); });

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
    db.get(`SELECT balance FROM users WHERE name = ?`, [name], (err, u) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!u) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
        if ((u.balance || 0) < price) return res.status(400).json({ error: `지갑 잔액 부족 (필요 ${price.toLocaleString()}원 / 보유 ${(u.balance||0).toLocaleString()}원)`, insufficient: true, need: price, balance: (u.balance||0), shortfall: price - (u.balance||0) });
        const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [price, name]);
            db.run(`INSERT INTO cloud_storage (name, purchasedBytes, usedBytes) VALUES (?, ?, 0) ON CONFLICT(name) DO UPDATE SET purchasedBytes = purchasedBytes + ?`, [name, addBytes, addBytes]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date, rawDate) VALUES (?, ?, ?, ?, ?)`, [name, 'RAYCloud 스토리지 충전', price, date, rawDate], function() {
                db.get(`SELECT purchasedBytes FROM cloud_storage WHERE name = ?`, [name], (e2, row) => {
                    const purchased = (row && row.purchasedBytes) || 0;
                    res.json({ success: true, price: price, addedGB: gb, balance: (u.balance - price), quotaBytes: CLOUD_FREE_BYTES + purchased });
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

app.post('/api/store/create', (req, res) => {
    db.get(`SELECT id FROM stores WHERE name = ?`, [req.body.name], (err, row) => {
        if (row) return res.status(400).json({ error: "이미 존재하는 명칭의 상점입니다." });
        const category = req.body.category || 'general';
        const bizType = req.body.bizType === 'individual' ? 'individual' : 'business';
        const bizNo = String(req.body.bizNo || '').replace(/\D/g, '');
        db.run(`INSERT INTO stores (id, name, owner, logo, status, background, description, category, bizType, bizNo) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`,
            ['STR_' + Date.now(), req.body.name, req.body.owner, req.body.logo, req.body.background || '', req.body.description || '', category, bizType, bizNo],
            () => res.json({ success: true }));
    });
});

// 🚀 상점 배경/소개/카테고리 업데이트
app.post('/api/store/update', (req, res) => {
    db.get(`SELECT owner FROM stores WHERE id = ?`, [req.body.id], (err, row) => {
        if(!row) return res.status(404).json({ error: "상점이 존재하지 않습니다." });
        if(row.owner !== req.body.owner) return res.status(403).json({ error: "본인 상점만 수정 가능합니다." });
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
app.post('/api/store/status', (req, res) => { db.run(`UPDATE stores SET status = ? WHERE id = ?`, [req.body.status, req.body.id], () => res.json({ success: true })); });

// 🚀 [v7p4] 상점 카테고리 변경 (본인 상점만)
app.post('/api/store/category', (req, res) => {
    const { id, category, owner } = req.body;
    if(!id || !category || !owner) return res.status(400).json({ error: 'id, category, owner 필수' });
    db.get(`SELECT owner FROM stores WHERE id = ?`, [id], (err, row) => {
        if(err || !row) return res.status(404).json({ error: '상점을 찾을 수 없음' });
        if(row.owner !== owner) return res.status(403).json({ error: '본인 상점만 수정 가능' });
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

        db.run(`INSERT INTO products (id, storeId, type, name, description, price_stream, price_original, stream_time, stream_unit, seller, thumbnail, encryptedPayload, compression_ratio, block_hash, ecc_signature, package_data, is_package) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [pid, req.body.storeId, req.body.name, req.body.description, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, Number(req.body.stream_time)||0, req.body.stream_unit, req.body.seller, req.body.thumbnail, req.body.encryptedPayload, ratio, block_hash, ecc_signature, packageData, isPackage], function(err) {
                if(err) return res.status(500).json({error: err.message});
                res.json({ success: true, id: pid, ratio, block_hash, ecc_signature });
            });
    } catch(err) { res.status(500).json({error: "상품 패키징 실패"}); }
});

// 🚀 구매 확정 시 작성된 폼 데이터 + 첨부 파일을 판매자에게 채팅으로 전달
// 🚀 [v6] 주문서 제출 (구매 확정 X → 'pending' 상태로 판매자 승인 대기)
app.post('/api/product/submit-order', (req, res) => {
    const { productId, buyer, seller, bundle_html, memo, form_data, pdf_filled_data, buyer_info, amount, status } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    const ordStatus = status || 'pending'; // 기본은 pending
    db.run(`INSERT INTO product_orders (productId, buyer, seller, bundle_html, memo, form_data, pdf_filled_data, buyer_info, status, amount, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [productId, buyer, seller, bundle_html || '', memo || '', JSON.stringify(form_data || {}), pdf_filled_data || '', JSON.stringify(buyer_info || {}), ordStatus, amount || 0, date],
        function(err) {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ success: true, orderId: this.lastID });
        });
});

// 🚀 [v6] 판매자가 주문 승인 → 결제 처리 + status='approved'
app.post('/api/order/approve', (req, res) => {
    const seller = requireUser(req, res); if (!seller) return;   // ★신원=토큰
    const { orderId } = req.body;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 승인할 수 있습니다.' });
        if(ord.status === 'approved') return res.json({ success: true, message: '이미 승인됨', txId: ord.txId });
        if(ord.status === 'rejected' || ord.status === 'cancelled') return res.status(400).json({ error: '취소/거절된 주문은 승인 불가' });

        const amount = ord.amount || 0;
        // ★배민식 카드수령 모델★: 승인 = 주문확정 + 매출기록만. 구매자 Earth 잔액을 차감/이체하지 않는다(결제는 Admin이 카드로 수령,
        //  업체 대금은 월정산으로 지급). 기존엔 구매자 잔액을 요구해 승인이 막히고 거래기록·구매내역이 비던 문제를 해결.
        db.get(`SELECT name FROM products WHERE id = ?`, [ord.productId], (e3, pRow) => {
            const pName = (pRow && pRow.name) || ord.productId;
            const date = new Date().toLocaleString('ko-KR');
            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, 'original', ?, ?)`,
                [ord.buyer, ord.seller, ord.productId, pName, amount, new Date().toISOString(), date],
                function(ie) {
                    if (ie) return res.status(500).json({ error: ie.message });
                    const txId = this.lastID;
                    db.run(`UPDATE product_orders SET status = 'approved', txId = ? WHERE id = ?`, [txId, orderId], () => res.json({ success: true, txId, amount }));
                });
        });
    });
});

// 🚀 [v6] 판매자가 주문 거절
app.post('/api/order/reject', (req, res) => {
    const seller = requireUser(req, res); if (!seller) return;   // ★신원=토큰
    const { orderId, reason } = req.body;
    db.get(`SELECT seller FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 거절할 수 있습니다.' });
        db.run(`UPDATE product_orders SET status = 'rejected', memo = COALESCE(memo, '') || ? WHERE id = ?`, ['\n[거절 사유] ' + (reason||''), orderId], () => res.json({ success: true }));
    });
});

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
            // ★환불 수락(배민식)★: 잔액 이동 없이 매출 취소 표시. 가드로 중복환불·미결제환불 차단.
            if (ord.status === 'refunded') return res.status(400).json({ error: '이미 환불 처리된 주문입니다.' });
            if (!['approved', 'shipping', 'delivered'].includes(ord.status)) return res.status(400).json({ error: '승인/배송 상태의 주문만 환불할 수 있습니다.' });
            const _finish = () => db.run(`UPDATE product_orders SET status = 'refunded' WHERE id = ?`, [orderId], () => res.json({ success: true }));
            if (ord.txId) {
                // 원 거래를 매출취소 처리 + 매출취소 거래기록 생성(거래내역·영수증·정산에 반영)
                db.get(`SELECT * FROM transactions WHERE id = ?`, [ord.txId], (e3, otx) => {
                    db.serialize(() => {
                        db.run(`UPDATE transactions SET refunded = 1 WHERE id = ?`, [ord.txId]);   // 매출 취소(구매내역·정산에서 제외)
                        if (otx) {
                            const now = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
                            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, refunded) VALUES (?, ?, ?, ?, ?, 'refund', ?, ?, 1)`,
                                [otx.seller, otx.buyer, otx.productId, `[매출취소] ${otx.productName || ''}`, otx.amount, rawDate, now]);
                        }
                        _finish();
                    });
                });
            } else { _finish(); }
        } else {
            db.run(`UPDATE product_orders SET status = ?, tracking = ?, courier = ? WHERE id = ?`, [status, tracking || ord.tracking || null, req.body.courier || ord.courier || null, orderId], () => res.json({ success: true }));
        }
    });
});

// 🚀 [v6] 단일 주문 조회 (orderId 기준; 채팅 카드 클릭 시 사용)
app.get('/api/order/:orderId', (req, res) => {
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [req.params.orderId], (err, row) => {
        if(err || !row) return res.status(404).json({ error: '주문 없음' });
        res.json(row);
    });
});

app.get('/api/product/orders/:seller', (req, res) => {
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
    const { userName } = req.body;
    if(!userName) return res.status(400).json({ error: 'userName 필수' });
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
    const { productId, buyer, seller, rating, review_text, skipped } = req.body;
    if(!productId || !buyer) return res.status(400).json({ error: 'productId, buyer 필수' });
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
    const { roomId, type, buyer, seller, storeId, storeName, lastProductId, lastProductName } = req.body;
    const now = new Date().toISOString();
    db.get(`SELECT id FROM chat_rooms WHERE roomId = ?`, [roomId], (err, row) => {
        if(row) {
            // 업데이트
            db.run(`UPDATE chat_rooms SET storeName = COALESCE(?, storeName), lastProductId = ?, lastProductName = ?, updated_at = ?, ended = 0 WHERE roomId = ?`,
                [storeName, lastProductId || null, lastProductName || null, now, roomId],
                () => res.json({ success: true, updated: true }));
        } else {
            db.run(`INSERT INTO chat_rooms (roomId, type, buyer, seller, storeId, storeName, lastProductId, lastProductName, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [roomId, type || 'order', buyer, seller, storeId || null, storeName || null, lastProductId || null, lastProductName || null, now, now],
                () => res.json({ success: true, created: true }));
        }
    });
});

// 🚀 [v6] 사용자의 채팅방 메타 일괄 조회 (양측 동기화 정보)
app.get('/api/chat-rooms/:user', (req, res) => {
    const user = req.params.user;
    db.all(`SELECT * FROM chat_rooms WHERE (buyer = ? OR seller = ?) AND ended = 0 ORDER BY updated_at DESC`, [user, user], (err, rows) => {
        res.json(rows || []);
    });
});

// 🚀 [v6] 채팅방 나가기 — order 타입은 양측 동시 종료
app.post('/api/chat-room/leave', (req, res) => {
    const { roomId, user } = req.body;
    db.get(`SELECT * FROM chat_rooms WHERE roomId = ?`, [roomId], (err, row) => {
        if(!row) {
            // 메타 없는 일반 친구 채팅 — 그냥 friends 삭제
            return res.json({ success: true, deleted: 'friend-only' });
        }
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
    db.all(`SELECT name, realname, phone, profilePic FROM users WHERE LOWER(name) LIKE ? OR LOWER(realname) LIKE ? OR phone LIKE ? LIMIT 20`, [like, like, like], (err, users) => {
        db.all(`SELECT id, name, owner, logo, category, description FROM stores WHERE status = 'active' AND LOWER(name) LIKE ? LIMIT 20`, [like], (err2, stores) => {
            res.json({ users: users || [], stores: stores || [] });
        });
    });
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/products/active', (req, res) => { db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' AND p.storeId NOT LIKE 'room_msg_%' ORDER BY p.id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => res.json(row || {})); });
app.post('/api/product/edit', (req, res) => { db.run(`UPDATE products SET name = ?, description = ?, stream_time = ?, stream_unit = ?, price_stream = ?, price_original = ? WHERE id = ?`, [req.body.name, req.body.description, Number(req.body.stream_time)||0, req.body.stream_unit, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, req.body.id], () => res.json({ success: true })); });

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
app.post('/api/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });

app.post('/api/buy', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // ★신원=토큰
    const amount = Number(req.body.amount) || 0; const pType = req.body.purchaseType; const rawDate = new Date().toISOString();
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "잔액 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [buyer, req.body.seller, req.body.productId, req.body.productName, amount, pType, rawDate, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
        });
    });
});

// 🚀 장바구니 일괄 결제 — 한 번에 결제하되 거래내역에는 개별 상품 단위로 기록 (환불 가능)
app.post('/api/buy/cart', (req, res) => {
    const buyer = requireUser(req, res); if (!buyer) return;   // ★신원=토큰
    const { items } = req.body; // items: [{productId, productName, seller, amount, purchaseType}]
    if(!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "장바구니가 비어있습니다." });
    const total = items.reduce((s, i) => s + (Number(i.amount) || 0), 0);
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if(!row || row.balance < total) return res.status(400).json({ error: `잔액 부족 (필요: ${total.toLocaleString()}원)` });
        // 같은 판매자에게 가는 금액들을 합산해서 한 번에 잔액 처리
        const sellerSums = {};
        items.forEach(i => { sellerSums[i.seller] = (sellerSums[i.seller] || 0) + Number(i.amount); });
        const now = new Date(); const dateStr = now.toLocaleString('ko-KR');
        db.serialize(() => {
            // 구매자 잔액 차감 (전체)
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [total, buyer]);
            // 판매자별 잔액 증가
            for(const seller in sellerSums) {
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [sellerSums[seller], seller]);
            }
            // 거래내역은 상품별로 개별 기록 (환불 단위 = 1개 상품)
            // rawDate에 마이크로초 오프셋을 추가해 정렬 순서 안정화
            let successCount = 0;
            items.forEach((it, idx) => {
                const itemRaw = new Date(now.getTime() + idx).toISOString();
                db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [buyer, it.seller, it.productId, it.productName, Number(it.amount) || 0, it.purchaseType || 'original', itemRaw, dateStr],
                    function(e) { if(!e) successCount++; if(idx === items.length - 1) res.json({ success: true, count: items.length, total }); });
            });
        });
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
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "발행 한도 초과" });
        const checkId = 'META_QR_' + Date.now(); const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
        const signature = generateECCInverseSignature(checkId, secretKey, amount); const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`, [checkId, amount, req.body.issuer, secretKey, signature, date]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, rawDate, date) VALUES (?, ?, ?, ?, ?, ?)`, [req.body.issuer, 'Earth(Root)', '보안 수표 발행', amount, rawDate, date], () => res.json({ success: true, checkId, secretKey, signature }));
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId, secretKey, signature } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`; let params = [checkId];
    if (secretKey && !checkId) { query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`; params = [secretKey]; }
    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "이미 회수되었거나 무효한 핀입니다." });
        const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
        db.serialize(() => {
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [row.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, rawDate, date) VALUES (?, ?, ?, ?, ?, ?)`, ['Earth(Root)', redeemer, '보안 수표 환원 충전', row.amount, rawDate, date], () => res.json({ success: true, amount: row.amount }));
        });
    });
});

app.post('/api/favorite/toggle', (req, res) => {
    db.get(`SELECT * FROM favorite_stores WHERE userName = ? AND targetStore = ?`, [req.body.userName, req.body.targetStore], (err, row) => {
        if(row) { db.run(`DELETE FROM favorite_stores WHERE id = ?`, [row.id], () => res.json({ success: true })); } 
        else { db.run(`INSERT INTO favorite_stores (userName, targetStore) VALUES (?, ?)`, [req.body.userName, req.body.targetStore], () => res.json({ success: true })); }
    });
});
app.get('/api/favorites/:userName', (req, res) => { db.all(`SELECT targetStore FROM favorite_stores WHERE userName = ?`, [req.params.userName], (err, rows) => res.json(rows ? rows.map(r => r.targetStore) : [])); });
// ⚡ 채팅 히스토리: 최근 N개만 반환(무제한 SELECT + base64 첨부 전송으로 인한 로딩 지연 해결). before 커서로 이전 대화 더보기.
app.get('/api/chat/:roomId', (req, res) => {
    const lim = Math.min(Number(req.query.limit) || 40, 100);
    const before = req.query.before ? Number(req.query.before) : null;
    const where = before ? `roomId = ? AND id < ?` : `roomId = ?`;
    const params = before ? [req.params.roomId, before] : [req.params.roomId];
    db.all(`SELECT * FROM (SELECT id, roomId, sender, senderPic, message, date FROM chats WHERE ${where} ORDER BY id DESC LIMIT ${lim}) ORDER BY id ASC`, params, (err, rows) => res.json(rows || []));
});

// 💬 채팅 첨부 업로드 — 파일을 로컬 디스크에 저장하고 접근 URL 반환(메시지에 URL만 담아 재전송 방지)
app.post('/api/chat/attach', (req, res) => {
    try {
        const { filename, dataBase64 } = req.body || {};
        if (!dataBase64) return res.status(400).json({ error: '데이터가 없습니다.' });
        const buf = Buffer.from(String(dataBase64), 'base64');
        if (!buf.length) return res.status(400).json({ error: '빈 파일입니다.' });
        if (buf.length > 300 * 1024 * 1024) return res.status(413).json({ error: '파일이 너무 큽니다(300MB 초과).' });
        let ext = path.extname(String(filename || '')).slice(0, 12).replace(/[^.\w]/g, '');
        if (!ext) ext = '.bin';
        const safe = 'att_' + Date.now() + '_' + crypto.randomBytes(8).toString('hex') + ext;
        fs.writeFileSync(path.join(CHAT_UPLOAD_DIR, safe), buf);
        const url = _shareBaseUrl(req) + '/chat-files/' + safe;
        res.json({ success: true, url, size: buf.length });
    } catch (e) { res.status(500).json({ error: (e && e.message) || '업로드 실패' }); }
});

// 🚀 [v5] 내 구매 목록 (구매자 관점, 상품 메타 + 환불 상태 JOIN)
app.get('/api/purchases/:buyer', async (req, res) => {
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
    db.get(`SELECT bundle_html, productId, buyer, seller FROM product_orders WHERE id = ?`, [req.params.orderId], (err, row) => {
        if(err || !row) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        res.json(row);
    });
});

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        // 🚀 환불 요청 상태 + 상품·상점 정보 JOIN
        const txQuery = `SELECT t.*,
            (SELECT status FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refund_status,
            (SELECT id FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refund_request_id,
            p.is_package as p_is_package, p.package_data as p_package_data, p.storeId as p_storeId,
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
            const refStatus = t.refund_status;
            const refundable = isBuyer && !t.refunded && refStatus !== 'pending'
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
                // 🧾 거래처 표기명(세금계산서와 통일): 상대방 실명(상호) → 없으면 브랜드 → ID
                counterpartyRealname: (isBuyer ? t.sellerRealname : t.buyerRealname) || null
            });
        });
        tfs.forEach(t => history.push({ type: t.sender === name ? '송금 (출금)' : '송금 (입금)', date: t.date, rawDate: t.rawDate || t.date, amount: t.amount, seller: t.receiver || t.sender, sender: t.sender, receiver: t.receiver }));
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
    const { txId, requester, reason } = req.body;
    db.get(`SELECT * FROM transactions WHERE id = ?`, [txId], (err, tx) => {
        if(!tx) return res.status(404).json({ error: "거래 내역을 찾을 수 없습니다." });
        if(tx.buyer !== requester) return res.status(403).json({ error: "구매자만 환불 요청할 수 있습니다." });
        if(tx.refunded) return res.status(400).json({ error: "이미 환불 처리된 거래입니다." });
        if(!tx.productId || tx.purchaseType === 'refund' || ['보안 수표 발행', '보안 수표 환원 충전'].includes(tx.productName)) {
            return res.status(400).json({ error: "해당 거래 유형은 환불할 수 없습니다." });
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

// 🚀 판매자에게 들어온 환불 요청 (승인/거절 대기)
app.get('/api/refunds/incoming/:name', (req, res) => {
    db.all(`SELECT * FROM refund_requests WHERE seller = ? AND status = 'pending' ORDER BY id DESC`, [req.params.name], (err, rows) => res.json(rows || []));
});
// 🚀 구매자가 보낸 모든 환불 요청 이력
app.get('/api/refunds/outgoing/:name', (req, res) => {
    db.all(`SELECT * FROM refund_requests WHERE buyer = ? ORDER BY id DESC`, [req.params.name], (err, rows) => res.json(rows || []));
});

// 🚀 판매자가 환불 승인/거절
app.post('/api/refund/decide', (req, res) => {
    const { requestId, decider, decision } = req.body; // decision: 'approve' | 'reject'
    db.get(`SELECT * FROM refund_requests WHERE id = ?`, [requestId], (err, rq) => {
        if(!rq) return res.status(404).json({ error: '환불 요청을 찾을 수 없습니다.' });
        if(rq.seller !== decider) return res.status(403).json({ error: '판매자만 결정할 수 있습니다.' });
        if(rq.status !== 'pending') return res.status(400).json({ error: '이미 처리된 요청입니다.' });
        const date = new Date().toLocaleString('ko-KR');
        if(decision === 'reject') {
            db.run(`UPDATE refund_requests SET status = 'rejected', decision_date = ? WHERE id = ?`, [date, requestId], () => res.json({ success: true, status: 'rejected' }));
        } else if(decision === 'approve') {
            db.get(`SELECT balance FROM users WHERE name = ?`, [rq.seller], (e2, sRow) => {
                if(!sRow) return res.status(404).json({ error: "판매자 계정 오류" });
                if(sRow.balance < rq.amount) return res.status(400).json({ error: "잔액 부족으로 환불 승인 불가" });
                const rawDate = new Date().toISOString();
                db.serialize(() => {
                    db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [rq.amount, rq.buyer]);
                    db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [rq.amount, rq.seller]);
                    db.run(`UPDATE transactions SET refunded = 1 WHERE id = ?`, [rq.txId]);
                    db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date, refunded) VALUES (?, ?, ?, ?, ?, 'refund', ?, ?, 1)`,
                        [rq.seller, rq.buyer, rq.productId, `[환불] ${rq.productName}`, rq.amount, rawDate, date]);
                    db.run(`UPDATE refund_requests SET status = 'approved', decision_date = ? WHERE id = ?`, [date, requestId],
                        () => res.json({ success: true, status: 'approved', amount: rq.amount }));
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
// 정산 변수 조회(기본값 포함)
function _taxConfig(cb){
    db.all(`SELECT key,value FROM settings WHERE key IN ('tax_vat_rate','tax_pay_fee_rate','tax_sw_fee')`, [], (e, rows) => {
        const m = {}; (rows||[]).forEach(r => m[r.key] = r.value);
        cb({ vatRate: parseFloat(m.tax_vat_rate)||10, payFeeRate: parseFloat(m.tax_pay_fee_rate)||2.7, swFee: parseInt(m.tax_sw_fee)||10000 });
    });
}
// 매출 → 정산 내역(수수료·VAT·지급액) 계산
function _settleCalc(salesTotal, cfg){
    salesTotal = _n(salesTotal);
    const payFee = Math.round(salesTotal * (cfg.payFeeRate/100));
    const swFee = _n(cfg.swFee);
    const feeSubtotal = payFee + swFee;
    const vatOnFees = Math.round(feeSubtotal * (cfg.vatRate/100));
    const commissionTotal = feeSubtotal + vatOnFees;   // 세금계산서 발행액(공급가=feeSubtotal, 세액=vatOnFees)
    const payout = salesTotal - commissionTotal;        // 업체 지급액
    return { salesTotal, payFee, swFee, feeSubtotal, vatOnFees, commissionTotal, payout };
}
const _salesWhere = `t.productId IS NOT NULL AND IFNULL(t.refunded,0)=0 AND t.purchaseType IS NOT NULL AND t.purchaseType NOT IN ('refund','signup_bonus')`;

// 팍스빌 연동 모드(live/mock)
app.get('/api/tax/config/status', (req, res) => { res.json(_paxbillStatus()); });
// 정산 변수 조회/변경(Admin)
app.get('/api/tax/config', (req, res) => { _taxConfig(cfg => res.json(cfg)); });
app.post('/api/tax/config', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const map = { tax_vat_rate: req.body.vatRate, tax_pay_fee_rate: req.body.payFeeRate, tax_sw_fee: req.body.swFee };
    const entries = Object.entries(map).filter(([k, v]) => v != null && v !== '');
    if (!entries.length) return _taxConfig(cfg => res.json({ success: true, config: cfg }));
    let n = 0; entries.forEach(([k, v]) => db.run(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [k, String(v)], () => { if (++n === entries.length) _taxConfig(cfg => res.json({ success: true, config: cfg })); }));
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
// Admin: 업체별 정산(매출 합계 + 수수료/VAT/지급액)
app.get('/api/admin/tax/settlement', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const month = String(req.query.month || '').slice(0, 7);
    _taxConfig((cfg) => {
        let where = _salesWhere; const params = [];
        if (month) { where += ` AND substr(IFNULL(t.rawDate,t.date),1,7)=?`; params.push(month); }
        db.all(`SELECT t.seller, COUNT(*) cnt, SUM(t.amount) salesTotal,
                    (SELECT realname FROM users WHERE name = t.seller) sellerRealname,
                    GROUP_CONCAT(DISTINCT p.storeId) storeIds,
                    GROUP_CONCAT(DISTINCT s.name) brands,
                    GROUP_CONCAT(DISTINCT t.productName) products
                FROM transactions t
                LEFT JOIN products p ON p.id = t.productId
                LEFT JOIN stores s ON p.storeId = s.id
                WHERE ${where} GROUP BY t.seller ORDER BY salesTotal DESC`, params, (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            const vendors = (rows || []).map(r => Object.assign({
                seller: r.seller, count: r.cnt,
                // 🧾 거래처 표기명 = 사업자등록증상 상호/실명(realname). 없으면 브랜드명, 그것도 없으면 ID.
                bizName: (r.sellerRealname && r.sellerRealname.trim()) || (r.brands ? String(r.brands).split(',')[0] : '') || r.seller,
                storeIds: r.storeIds || '', brands: r.brands || '', products: r.products || ''
            }, _settleCalc(r.salesTotal, cfg)));
            res.json({ month, config: cfg, vendors });
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
    const item = b.item || {};
    const supplyAmount = _n(b.supplyAmount != null ? b.supplyAmount : item.supplyAmount);
    let taxAmount = _n(b.taxAmount != null ? b.taxAmount : item.taxAmount);
    let totalAmount = _n(b.totalAmount != null ? b.totalAmount : (supplyAmount + taxAmount));
    if (!totalAmount) totalAmount = supplyAmount + taxAmount;
    if (!supplier.name || !_digits(supplier.bizNo)) throw new Error('공급자(플랫폼) 상호·사업자번호를 입력하세요.');
    if (totalAmount <= 0) throw new Error('발행 금액이 0원입니다.');
    const payload = {
        documentType: 'tax_invoice', issueType: 'normal', purposeType: b.purposeType || 'receipt', taxType: 'taxable',
        writeDate: b.writeDate || new Date().toISOString().slice(0, 10), supplyDate: b.supplyDate || null, sendToNts: true,
        seller, buyer: b.buyer || '', batchMonth: b.batchMonth || null,
        supplier: { bizNo:_digits(supplier.bizNo), name:String(supplier.name||''), ceoName:String(supplier.ceoName||''), address:String(supplier.address||''), bizType:String(supplier.bizType||''), bizClass:String(supplier.bizClass||''), email:String(supplier.email||''), phone:String(supplier.phone||'') },
        recipient: { bizNo:_digits(recipient.bizNo), name:String(recipient.name||seller), ceoName:String(recipient.ceoName||''), address:String(recipient.address||''), bizType:String(recipient.bizType||''), bizClass:String(recipient.bizClass||''), email:String(recipient.email||''), phone:String(recipient.phone||'') },
        items: [{ name:String(item.name||'플랫폼 이용 수수료'), spec:String(item.spec||''), qty:Number(item.qty)||1, supplyAmount, taxAmount, totalAmount, remark:String(item.remark||'') }],
        amounts: { supplyAmount, taxAmount, totalAmount }, memo: String(b.memo || '')
    };
    const pax = await _postToPaxbill('issue', payload);
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

// 🔐 방(room_msg_a_b) 참가자 도출 — 개인 룸 대상 전송용
function _roomParticipants(roomId) { return String(roomId || '').replace('room_msg_', '').split('_').filter(Boolean); }
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
    socket.on('send_message', (data) => {
        if (!data || !data.roomId) return;
        // 인증 소켓이면 발신자를 토큰 신원으로 강제(위조 차단). '__system__'은 시스템 메시지로 허용. 미인증 소켓은 레거시 호환 허용.
        const isSystem = data.sender === '__system__';
        if (socket.data.user && !isSystem && data.sender && data.sender !== socket.data.user) return;
        const sender = isSystem ? '__system__' : (socket.data.user || data.sender);
        const users = _roomParticipants(data.roomId);
        if (users.length === 2) {
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[0], users[1]]);
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[1], users[0]]);
        }
        // senderPic(base64)은 DB 미저장(히스토리 경량화). 실시간엔 실어 보냄. 아래는 참가자 개인 룸에만 전송.
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date) VALUES (?, ?, ?, ?, ?)`, [data.roomId, sender, null, data.message, new Date().toLocaleString('ko-KR')], function() {
            _emitToRoomUsers(data.roomId, 'receive_message', Object.assign({}, data, { sender, id: this.lastID }));
        });
    });
    // 메시지 수정 (작성자만 — 인증 소켓이면 토큰 신원으로 판정)
    socket.on('edit_message', (data) => {
        if (!data || !data.id) return;
        const sender = socket.data.user || data.sender;
        db.run(`UPDATE chats SET message = ? WHERE id = ? AND sender = ?`, [data.message, data.id, sender], function() {
            if (this.changes) _emitToRoomUsers(data.roomId, 'message_edited', { id: data.id, roomId: data.roomId, message: data.message, sender });
        });
    });
    // 메시지 삭제 (작성자만)
    socket.on('delete_message', (data) => {
        if (!data || !data.id) return;
        const sender = socket.data.user || data.sender;
        db.run(`DELETE FROM chats WHERE id = ? AND sender = ?`, [data.id, sender], function() {
            if (this.changes) _emitToRoomUsers(data.roomId, 'message_deleted', { id: data.id, roomId: data.roomId, sender });
        });
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[EARTH MASTER VER] BOUND ON PORT ${PORT}`); });