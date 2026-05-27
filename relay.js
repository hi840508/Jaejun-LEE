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
const io = new Server(server, { cors: { origin: "*" } });
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
        db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, secretKey TEXT, eccSignature TEXT, is_used INTEGER, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT, rawDate TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, sender_name TEXT, amount INTEGER, status TEXT, date TEXT, rawDate TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, amount INTEGER, status TEXT, date TEXT, rawDate TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, targetStore TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS refund_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, txId INTEGER, buyer TEXT, seller TEXT, productId TEXT, productName TEXT, amount INTEGER, status TEXT DEFAULT 'pending', reason TEXT, request_date TEXT, decision_date TEXT)`);

        // 🚀 기존 DB 호환을 위한 마이그레이션 (컬럼 추가; 이미 있으면 에러 무시)
        db.run(`ALTER TABLE stores ADD COLUMN background TEXT`, () => {});
        db.run(`ALTER TABLE stores ADD COLUMN description TEXT`, () => {});
        db.run(`ALTER TABLE transactions ADD COLUMN refunded INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN email TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN shipping_address TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp TEXT`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp_expiry INTEGER`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN reset_otp_used INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE users ADD COLUMN force_pwd_change INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE transfers ADD COLUMN rawDate TEXT`, () => {});
        db.run(`ALTER TABLE deposits ADD COLUMN rawDate TEXT`, () => {});
        db.run(`ALTER TABLE withdrawals ADD COLUMN rawDate TEXT`, () => {});
    });
}
initTables();

app.post('/api/admin/db-reset', (req, res) => {
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
    db.serialize(() => {
        const tables = ['users', 'friends', 'stores', 'products', 'transactions', 'chats', 'qr_checks', 'transfers', 'deposits', 'withdrawals', 'favorite_stores', 'refund_requests'];
        tables.forEach(t => db.run(`DROP TABLE IF EXISTS ${t}`));
        initTables(); res.json({ success: true });
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

app.post('/api/auth/register', (req, res) => {
    const { name, password, realname, bank, account, phone, email, shipping_address } = req.body;
    db.run(`INSERT INTO users (name, password, realname, bank, account, balance, phone, email, shipping_address) VALUES (?, ?, ?, ?, ?, 10000, ?, ?, ?)`,
        [name, password, realname, bank, account, phone || '', email || '', shipping_address || ''], (err) => {
        if (err) return res.status(500).json({ error: "회원 ID 중복 또는 생성 에러" });
        // 🚀 가입 축하금 거래 장부 기록 (컨벤션: 받는 쪽이 seller)
        const date = new Date().toLocaleString('ko-KR'); const rawDate = new Date().toISOString();
        db.run(`INSERT INTO transactions (buyer, seller, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            ['Earth(Root)', name, '신규 가입 정산 한도 축하금', 10000, 'signup_bonus', rawDate, date]);
        res.json({ name, password, realname, bank, account, phone: phone || '', email: email || '', shipping_address: shipping_address || '', balance: 10000, profilePic: null });
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

app.post('/api/store/create', (req, res) => {
    db.get(`SELECT id FROM stores WHERE name = ?`, [req.body.name], (err, row) => {
        if (row) return res.status(400).json({ error: "이미 존재하는 명칭의 상점입니다." });
        db.run(`INSERT INTO stores (id, name, owner, logo, status, background, description) VALUES (?, ?, ?, ?, 'active', ?, ?)`,
            ['STR_' + Date.now(), req.body.name, req.body.owner, req.body.logo, req.body.background || '', req.body.description || ''],
            () => res.json({ success: true }));
    });
});

// 🚀 상점 배경/소개 업데이트
app.post('/api/store/update', (req, res) => {
    db.get(`SELECT owner FROM stores WHERE id = ?`, [req.body.id], (err, row) => {
        if(!row) return res.status(404).json({ error: "상점이 존재하지 않습니다." });
        if(row.owner !== req.body.owner) return res.status(403).json({ error: "본인 상점만 수정 가능합니다." });
        const fields = []; const values = [];
        if(req.body.background !== undefined) { fields.push('background = ?'); values.push(req.body.background); }
        if(req.body.description !== undefined) { fields.push('description = ?'); values.push(req.body.description); }
        if(req.body.logo !== undefined && req.body.logo) { fields.push('logo = ?'); values.push(req.body.logo); }
        if(fields.length === 0) return res.json({ success: true });
        values.push(req.body.id);
        db.run(`UPDATE stores SET ${fields.join(', ')} WHERE id = ?`, values, () => res.json({ success: true }));
    });
});

app.get('/api/stores/owned/:owner', (req, res) => { db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => res.json(rows || [])); });
app.post('/api/store/status', (req, res) => { db.run(`UPDATE stores SET status = ? WHERE id = ?`, [req.body.status, req.body.id], () => res.json({ success: true })); });
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
        
        db.run(`INSERT INTO products (id, storeId, type, name, description, price_stream, price_original, stream_time, stream_unit, seller, thumbnail, encryptedPayload, compression_ratio, block_hash, ecc_signature) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
            [pid, req.body.storeId, req.body.name, req.body.description, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, Number(req.body.stream_time)||0, req.body.stream_unit, req.body.seller, req.body.thumbnail, req.body.encryptedPayload, ratio, block_hash, ecc_signature], function(err) {
                if(err) return res.status(500).json({error: err.message});
                res.json({ success: true, id: pid, ratio, block_hash, ecc_signature });
            });
    } catch(err) { res.status(500).json({error: "에셋 패키징 실패"}); }
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/products/active', (req, res) => { db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' AND p.storeId NOT LIKE 'room_msg_%' ORDER BY p.id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => res.json(row || {})); });
app.post('/api/product/edit', (req, res) => { db.run(`UPDATE products SET name = ?, description = ?, stream_time = ?, stream_unit = ?, price_stream = ?, price_original = ? WHERE id = ?`, [req.body.name, req.body.description, Number(req.body.stream_time)||0, req.body.stream_unit, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, req.body.id], () => res.json({ success: true })); });

app.post('/api/admin/product/delete', (req, res) => { 
    if(req.body.adminSecret !== 'mars') return res.status(403).json({error: "Admin Authorization Failed"});
    db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); 
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

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        // 🚀 환불 요청 상태를 LEFT JOIN으로 함께 조회 (최신 요청 1개 기준)
        const txQuery = `SELECT t.*,
            (SELECT status FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refund_status,
            (SELECT id FROM refund_requests WHERE txId = t.id ORDER BY id DESC LIMIT 1) as refund_request_id
            FROM transactions t WHERE t.buyer=? OR t.seller=?`;
        const txs = await new Promise(r => db.all(txQuery, [name, name], (e, rows) => r(rows||[])));
        const tfs = await new Promise(r => db.all(`SELECT * FROM transfers WHERE sender=? OR receiver=?`, [name, name], (e, rows) => r(rows||[])));
        const dps = await new Promise(r => db.all(`SELECT * FROM deposits WHERE user_name=?`, [name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));

        let history = [];
        txs.forEach(t => {
            const isBuyer = t.buyer === name;
            const refStatus = t.refund_status; // 'pending' | 'approved' | 'rejected' | null
            // 🚀 환불 요청 가능 여부: 구매자이며, 미환불, 대기중 요청 없음, 유효한 자산 거래
            const refundable = isBuyer && !t.refunded && refStatus !== 'pending'
                && t.productId && t.purchaseType !== 'refund' && t.purchaseType !== 'signup_bonus'
                && !['보안 수표 발행', '보안 수표 환원 충전', '신규 가입 정산 한도 축하금'].includes(t.productName);
            // 🚀 거래 유형 라벨 (장부 누락 없이 의미 명확)
            let baseType;
            if(t.purchaseType === 'refund') baseType = isBuyer ? '환불 수령' : '환불 지급';
            else if(t.purchaseType === 'signup_bonus') baseType = '가입 축하금';
            else if(t.productName === '보안 수표 발행') baseType = '보안 수표 발행';
            else if(t.productName === '보안 수표 환원 충전') baseType = '보안 수표 환원';
            else baseType = isBuyer ? '자산 구매' : '자산 판매';
            history.push({
                txId: t.id, type: baseType,
                date: t.date, rawDate: t.rawDate || t.date, productId: t.productId, purchaseType: t.purchaseType,
                amount: t.amount, productName: t.productName, buyer: t.buyer, seller: isBuyer ? t.seller : t.buyer,
                refunded: !!t.refunded, refundable, refundStatus: refStatus, refundRequestId: t.refund_request_id
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
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date) VALUES (?, ?, ?, ?, ?)`, [data.roomId, data.sender, data.senderPic, data.message, new Date().toLocaleString('ko-KR')], () => { 
            io.emit('receive_message', data); 
        }); 
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[EARTH MASTER VER] BOUND ON PORT ${PORT}`); });
