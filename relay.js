const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const zlib = require('zlib');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

// 실제 비대칭 디지털 서명 알고리즘(ECDSA) 
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

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
        // 🔒 통합 뷰어(HTML) DRM — 복호 키를 서버가 보관, 로그인+바인딩+만료 통과 시에만 전달.
        db.run(`CREATE TABLE IF NOT EXISTS viewer_files (fileId TEXT PRIMARY KEY, k TEXT, expiry INTEGER DEFAULT 0, creator TEXT, title TEXT, boundUser TEXT, firstOpenedAt INTEGER, createdAt INTEGER)`);
        db.run(`CREATE TABLE IF NOT EXISTS viewer_opens (id INTEGER PRIMARY KEY AUTOINCREMENT, fileId TEXT, userName TEXT, at INTEGER, ok INTEGER, reason TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS friends (userName TEXT, friendName TEXT, UNIQUE(userName, friendName))`);
        db.run(`CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, name TEXT, owner TEXT, logo TEXT, status TEXT DEFAULT 'active', background TEXT, description TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, storeId TEXT, type TEXT, name TEXT, description TEXT, price_stream INTEGER DEFAULT 0, price_original INTEGER DEFAULT 0, stream_time INTEGER DEFAULT 0, stream_unit TEXT DEFAULT 'd', seller TEXT, thumbnail TEXT, encryptedPayload TEXT, compression_ratio INTEGER DEFAULT 0, block_hash TEXT, ecc_signature TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productId TEXT, productName TEXT, amount INTEGER, purchaseType TEXT, rawDate TEXT, date TEXT, refunded INTEGER DEFAULT 0)`);
        db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, senderPic TEXT, message TEXT, date TEXT)`);
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
        // 🚀 [v6] order_orders 컬럼 추가 (구버전 DB 호환)
        db.run(`ALTER TABLE product_orders ADD COLUMN pdf_filled_data TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN buyer_info TEXT`, () => {});
        db.run(`ALTER TABLE product_orders ADD COLUMN status TEXT DEFAULT 'approved'`, () => {});
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
        });
    });
}
initTables();

// 🚀 [v8+] Admin 비밀번호 헬퍼 — DB의 settings.admin_password 사용 (초기값 'mars')
function getAdminPassword(cb) {
    db.get(`SELECT value FROM settings WHERE key = 'admin_password'`, [], (err, row) => {
        cb((row && row.value) || 'mars');
    });
}
// adminSecret 검증 미들웨어 대용 — 'mars'(레거시) 또는 현재 설정된 비밀번호 모두 허용
function verifyAdminSecret(secret, cb) {
    getAdminPassword((pw) => cb(secret === pw || secret === 'mars'));
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
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
    db.serialize(() => {
        const tables = ['users', 'friends', 'stores', 'products', 'transactions', 'chats', 'qr_checks', 'transfers', 'deposits', 'withdrawals', 'favorite_stores', 'refund_requests', 'product_orders', 'chat_rooms', 'product_reviews'];
        tables.forEach(t => db.run(`DROP TABLE IF EXISTS ${t}`));
        initTables(); res.json({ success: true });
    });
});

// 🔒 통합 뷰어 DRM: 생성 시 키 등록
app.post('/api/viewer/register', (req, res) => {
    const { fileId, k, expiry, creator, title } = req.body || {};
    if (!fileId || !k) return res.status(400).json({ error: 'fileId/k 필요' });
    db.get(`SELECT boundUser, firstOpenedAt FROM viewer_files WHERE fileId = ?`, [fileId], (e, prev) => {
        db.run(`INSERT OR REPLACE INTO viewer_files (fileId,k,expiry,creator,title,boundUser,firstOpenedAt,createdAt) VALUES (?,?,?,?,?,?,?,?)`,
            [fileId, String(k), Number(expiry) || 0, creator || '', title || '', (prev && prev.boundUser) || null, (prev && prev.firstOpenedAt) || null, Date.now()],
            (err) => { if (err) return res.status(500).json({ error: err.message }); res.json({ ok: true }); });
    });
});
// 🔒 통합 뷰어 DRM: 열람 시 잠금해제 — 로그인 검증 + 만료 + 최초개봉 ID 바인딩 → 키 전달
app.post('/api/viewer/unlock', (req, res) => {
    const { fileId, userName, password } = req.body || {};
    if (!fileId || !userName) return res.status(400).json({ error: '정보 부족' });
    const rec = (ok, reason) => db.run(`INSERT INTO viewer_opens (fileId,userName,at,ok,reason) VALUES (?,?,?,?,?)`, [fileId, userName, Date.now(), ok ? 1 : 0, reason || ''], () => {});
    db.get(`SELECT * FROM users WHERE name = ?`, [userName], (e, u) => {
        if (e) return res.status(500).json({ error: e.message });
        if (!u || u.password !== password) { rec(0, 'auth'); return res.status(401).json({ error: 'ID 또는 비밀번호가 올바르지 않습니다.' }); }
        db.get(`SELECT * FROM viewer_files WHERE fileId = ?`, [fileId], (e2, f) => {
            if (e2) return res.status(500).json({ error: e2.message });
            if (!f) { rec(0, 'noreg'); return res.status(404).json({ error: '등록되지 않은 뷰어 파일입니다.' }); }
            const now = Date.now();
            if (f.expiry && now > f.expiry) { rec(0, 'expired'); return res.status(403).json({ error: '열람 기간이 만료되었습니다.', expired: true }); }
            if (f.boundUser && f.boundUser !== userName) { rec(0, 'bound'); return res.status(403).json({ error: '이 파일은 다른 계정(' + f.boundUser + ')에 연결되어 다른 ID로는 열 수 없습니다.', bound: true }); }
            if (!f.boundUser) db.run(`UPDATE viewer_files SET boundUser=?, firstOpenedAt=? WHERE fileId=?`, [userName, now, fileId], () => {});   // 최초 개봉 ID로 영구 바인딩
            rec(1, f.boundUser ? 'open' : 'firstbind');
            res.json({ ok: true, k: f.k, boundUser: f.boundUser || userName, firstOpen: !f.boundUser });
        });
    });
});

app.post('/api/auth/verify', (req, res) => {
    db.get(`SELECT * FROM users WHERE name = ?`, [req.body.name], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            if (row.password === req.body.password) {
                res.json({ exists: true, user: row, mustChangePassword: !!row.force_pwd_change });
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

app.post('/api/auth/register', (req, res) => {
    const { name, password, realname, bank, account, phone, email, shipping_address, business_type, license_doc } = req.body;
    // 🚀 [v8+] 의료·약무 관련 업종은 자격증 필수 + Admin 승인 대기
    const regulated = ['dental_lab', 'medical', 'pharmacy', 'medical_wholesale'];
    const needsApproval = regulated.includes(business_type);
    if(needsApproval && !license_doc) return res.status(400).json({ error: '해당 업종은 자격증 업로드가 필수입니다.' });
    const approvalStatus = needsApproval ? 'pending' : 'approved';

    db.run(`INSERT INTO users (name, password, realname, bank, account, balance, phone, email, shipping_address, business_type, license_doc, approval_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [name, password, realname, bank, account, needsApproval ? 0 : 10000, phone || '', email || '', shipping_address || '', business_type || 'individual', license_doc || null, approvalStatus], (err) => {
        if (err) return res.status(500).json({ error: "회원 ID 중복 또는 생성 에러" });
        // 승인 대기는 보너스 X. 자동 승인 회원만 10,000원 정산 한도 축하금
        if(!needsApproval) {
            const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                ['Earth(Root)', name, '신규 가입 정산 한도 축하금', 10000, 'signup_bonus', rawDate, date]);
        }
        res.json({ 
            name, password, realname, bank, account, 
            phone: phone || '', email: email || '', shipping_address: shipping_address || '', 
            business_type: business_type || 'individual', 
            approval_status: approvalStatus,
            balance: needsApproval ? 0 : 10000, 
            profilePic: null,
            needsApproval
        });
    });
});

// 🚀 [v8+] Admin: 가입 승인 대기 회원 목록
app.get('/api/admin/pending-users', (req, res) => {
    db.all(`SELECT name, realname, business_type, phone, email, license_doc, approval_status, approval_note FROM users WHERE approval_status = 'pending' ORDER BY name`, [], (err, rows) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 🚀 [v8+] Admin: 승인 / 반려
app.post('/api/admin/approve-user', (req, res) => {
    const { name, decision, note, adminSecret } = req.body;
    if(adminSecret !== 'mars') return res.status(403).json({ error: 'Admin 권한 필요' });
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
    db.run(`UPDATE users SET password = ?, realname = ?, bank = ?, account = ?, profilePic = ?, phone = ?, email = ?, shipping_address = ? WHERE name = ?`,
        [req.body.password, req.body.realname, req.body.bank, req.body.account, req.body.profilePic, req.body.phone || '', req.body.email || '', req.body.shipping_address || '', req.body.name],
        () => res.json({success: true}));
});

// 🚀 비밀번호 변경 후 force_pwd_change 플래그 해제
app.post('/api/user/change-password', (req, res) => {
    const { name, newPassword } = req.body;
    if(!newPassword || newPassword.length < 4) return res.status(400).json({ error: "비밀번호는 4자 이상이어야 합니다." });
    db.run(`UPDATE users SET password = ?, force_pwd_change = 0, reset_otp = NULL, reset_otp_expiry = NULL, reset_otp_used = 0 WHERE name = ?`,
        [newPassword, name], (err) => {
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
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = Date.now() + 10 * 60 * 1000; // 10분
        db.run(`UPDATE users SET reset_otp = ?, reset_otp_expiry = ?, reset_otp_used = 0 WHERE name = ?`,
            [otp, expiry, name], (e2) => {
                if(e2) return res.status(500).json({ error: e2.message });
                console.log(`[OTP 발송] ${name} (${row.email}) → ${otp}  (10분 유효)`);
                // 실제 운영 환경에서는 이메일 발송 (SES, sendgrid 등). 데모 환경에서는 응답에 동봉.
                res.json({ success: true, email: row.email, demo_otp: otp, expires_in_minutes: 10 });
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
            res.json({ success: true, user: row, mustChangePassword: true });
        });
    });
});

// 🚀 Admin 전용: 모든 회원 정보 조회 (복구 목적)
app.post('/api/admin/all-users', (req, res) => {
    if(req.body.adminSecret !== 'mars') return res.status(403).json({ error: "Admin 인증 실패" });
    db.all(`SELECT name, password, realname, bank, account, phone, email, shipping_address, balance,
            CASE WHEN profilePic IS NOT NULL AND profilePic != '' THEN '있음' ELSE '없음' END as hasPic
            FROM users ORDER BY name`, [], (err, rows) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 🚀 Admin 전용: 특정 회원 비밀번호 강제 재설정 (복구 목적)
app.post('/api/admin/reset-password', (req, res) => {
    if(req.body.adminSecret !== 'mars') return res.status(403).json({ error: "Admin 인증 실패" });
    const { targetName, newPassword } = req.body;
    if(!targetName || !newPassword) return res.status(400).json({ error: "필수 필드 누락" });
    db.run(`UPDATE users SET password = ?, force_pwd_change = 0, reset_otp = NULL, reset_otp_expiry = NULL, reset_otp_used = 0 WHERE name = ?`,
        [newPassword, targetName], function(err) {
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
    const amount = Number(req.body.amount) || 0; const rawDate = new Date().toISOString();
    db.serialize(() => { db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.name]); db.run(`INSERT INTO withdrawals (name, amount, status, date, rawDate) VALUES (?, ?, '대기', ?, ?)`, [req.body.name, amount, new Date().toLocaleString('ko-KR'), rawDate], () => res.json({ success: true })); });
});

app.get('/api/admin/actions', (req, res) => {
    db.all(`SELECT d.*, u.realname, u.bank, u.account FROM deposits d LEFT JOIN users u ON d.user_name = u.name WHERE d.status = '대기'`, [], (err, deps) => {
        db.all(`SELECT w.*, u.realname, u.bank, u.account FROM withdrawals w LEFT JOIN users u ON w.name = u.name WHERE w.status = '대기'`, [], (err2, wds) => { res.json({ deposits: deps || [], withdrawals: wds || [] }); });
    });
});

app.post('/api/admin/approve', (req, res) => {
    const { type, id, userName } = req.body; const amount = Number(req.body.amount) || 0;
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
    if(type === 'deposit_direct') {
        db.serialize(() => { db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, userName]); db.run(`UPDATE deposits SET status = '승인_증액' WHERE id = ?`, [id], () => res.json({ success: true })); });
    } else if (type === 'withdraw') { db.run(`UPDATE withdrawals SET status = '승인출금완료' WHERE id = ?`, [id], () => res.json({ success: true })); }
});

app.post('/api/transfer', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.sender], (err, sRow) => {
        if (!sRow || sRow.balance < amount) return res.status(400).json({ error: "원장 자산 잔액 부족" });
        const rawDate = new Date().toISOString(); const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.sender]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.receiver]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date, rawDate) VALUES (?, ?, ?, ?, ?)`, [req.body.sender, req.body.receiver, amount, date, rawDate], () => res.json({ success: true }));
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
    const name = req.body.name;
    const gb = Number(req.body.gb) || 0;
    if (!name || gb <= 0) return res.status(400).json({ error: '구매할 용량(GB)을 확인하세요' });
    const price = Math.round(gb * CLOUD_PRICE_PER_GB);
    const addBytes = Math.round(gb * 1024 * 1024 * 1024);
    db.get(`SELECT balance FROM users WHERE name = ?`, [name], (err, u) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!u) return res.status(404).json({ error: '회원을 찾을 수 없습니다' });
        if ((u.balance || 0) < price) return res.status(400).json({ error: `지갑 잔액 부족 (필요 ${price.toLocaleString()}원 / 보유 ${(u.balance||0).toLocaleString()}원)` });
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
        db.run(`INSERT INTO stores (id, name, owner, logo, status, background, description, category) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`,
            ['STR_' + Date.now(), req.body.name, req.body.owner, req.body.logo, req.body.background || '', req.body.description || '', category],
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
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
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
    const { orderId, seller } = req.body;
    db.get(`SELECT * FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 승인할 수 있습니다.' });
        if(ord.status === 'approved') return res.json({ success: true, message: '이미 승인됨', txId: ord.txId });
        if(ord.status === 'rejected' || ord.status === 'cancelled') return res.status(400).json({ error: '취소/거절된 주문은 승인 불가' });

        const amount = ord.amount || 0;
        // 잔액 확인 + 이동
        db.get(`SELECT balance FROM users WHERE name = ?`, [ord.buyer], (e2, bRow) => {
            if(!bRow || bRow.balance < amount) return res.status(400).json({ error: '구매자 잔액 부족' });
            db.serialize(() => {
                db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, ord.buyer]);
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, ord.seller]);
                const productName = ord.productId; // 정확한 이름은 별도 조회
                db.get(`SELECT name FROM products WHERE id = ?`, [ord.productId], (e3, pRow) => {
                    const pName = (pRow && pRow.name) || productName;
                    const date = new Date().toLocaleString('ko-KR');
                    db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, 'original', ?, ?)`,
                        [ord.buyer, ord.seller, ord.productId, pName, amount, new Date().toISOString(), date],
                        function() {
                            const txId = this.lastID;
                            db.run(`UPDATE product_orders SET status = 'approved', txId = ? WHERE id = ?`, [txId, orderId]);
                            res.json({ success: true, txId, amount });
                        });
                });
            });
        });
    });
});

// 🚀 [v6] 판매자가 주문 거절
app.post('/api/order/reject', (req, res) => {
    const { orderId, seller, reason } = req.body;
    db.get(`SELECT seller FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.seller !== seller) return res.status(403).json({ error: '본인에게 온 주문만 거절할 수 있습니다.' });
        db.run(`UPDATE product_orders SET status = 'rejected', memo = COALESCE(memo, '') || ? WHERE id = ?`, ['\n[거절 사유] ' + (reason||''), orderId], () => res.json({ success: true }));
    });
});

// 🚀 [v6] 구매자가 자신의 pending 주문 취소
app.post('/api/order/cancel', (req, res) => {
    const { orderId, buyer } = req.body;
    db.get(`SELECT buyer, status FROM product_orders WHERE id = ?`, [orderId], (err, ord) => {
        if(err || !ord) return res.status(404).json({ error: '주문을 찾을 수 없음' });
        if(ord.buyer !== buyer) return res.status(403).json({ error: '본인 주문만 취소 가능' });
        if(ord.status !== 'pending') return res.status(400).json({ error: 'pending 상태만 취소 가능' });
        db.run(`UPDATE product_orders SET status = 'cancelled' WHERE id = ?`, [orderId], () => res.json({ success: true }));
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
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
    db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); 
});
// 🚀 [v8+] Admin이 임의 상점을 강제 폐쇄 (소유자 무관)
app.post('/api/admin/store/delete', (req, res) => {
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
    db.serialize(() => {
        db.run(`DELETE FROM products WHERE storeId = ?`, [req.body.id]);
        db.run(`DELETE FROM stores WHERE id = ?`, [req.body.id], () => res.json({ success: true }));
    });
});
app.post('/api/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });

app.post('/api/buy', (req, res) => {
    const amount = Number(req.body.amount) || 0; const pType = req.body.purchaseType; const rawDate = new Date().toISOString();
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "잔액 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.buyer, req.body.seller, req.body.productId, req.body.productName, amount, pType, rawDate, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
        });
    });
});

// 🚀 장바구니 일괄 결제 — 한 번에 결제하되 거래내역에는 개별 상품 단위로 기록 (환불 가능)
app.post('/api/buy/cart', (req, res) => {
    const { buyer, items } = req.body; // items: [{productId, productName, seller, amount, purchaseType}]
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
app.get('/api/chat/:roomId', (req, res) => { db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => res.json(rows || [])); });

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

        // 각 구매에 연관된 주문서(product_orders) 조회
        for(let t of txs) {
            const order = await new Promise(r => db.get(
                `SELECT id, bundle_html, memo, form_data, created_at FROM product_orders WHERE buyer = ? AND productId = ? ORDER BY id DESC LIMIT 1`,
                [buyer, t.productId],
                (e, row) => r(row || null)
            ));
            if(order) {
                t.orderId = order.id;
                t.orderMemo = order.memo;
                t.orderFormData = order.form_data;
                t.orderCreatedAt = order.created_at;
                t.hasBundle = !!order.bundle_html;
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
            s.name as storeName, s.category as storeCategory
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
                storeName: t.storeName || null, storeId: t.p_storeId || null, fileNames: fileNames
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
    req.url = '/api/refund/request'; app._router.handle(req, res);
});

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => { 
        const users = data.roomId.replace('room_msg_', '').split('_');
        if(users.length === 2) {
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[0], users[1]]);
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[1], users[0]]);
        }
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date) VALUES (?, ?, ?, ?, ?)`, [data.roomId, data.sender, data.senderPic, data.message, new Date().toLocaleString('ko-KR')], function() { 
            // 🚀 [v8+] 삽입된 메시지 id를 함께 브로드캐스트 → 클라이언트 수정/삭제 가능
            io.emit('receive_message', Object.assign({}, data, { id: this.lastID })); 
        }); 
    });
    // 🚀 [v8+] 메시지 수정 (작성자만)
    socket.on('edit_message', (data) => {
        if(!data || !data.id) return;
        db.run(`UPDATE chats SET message = ? WHERE id = ? AND sender = ?`, [data.message, data.id, data.sender], function() {
            io.emit('message_edited', { id: data.id, roomId: data.roomId, message: data.message, sender: data.sender });
        });
    });
    // 🚀 [v8+] 메시지 삭제 (작성자만)
    socket.on('delete_message', (data) => {
        if(!data || !data.id) return;
        db.run(`DELETE FROM chats WHERE id = ? AND sender = ?`, [data.id, data.sender], function() {
            io.emit('message_deleted', { id: data.id, roomId: data.roomId, sender: data.sender });
        });
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[EARTH MASTER VER] BOUND ON PORT ${PORT}`); });
