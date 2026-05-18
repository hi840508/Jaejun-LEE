const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = 4000;

// 🚀 자산 증발을 영구 차단하기 위해 리눅스 최상위 경로로 DB 격리 배치
const db = new sqlite3.Database('/home/ubuntu/earth_production_master.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER, profilePic TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS friends (userName TEXT, friendName TEXT, UNIQUE(userName, friendName))`);
    db.run(`CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, name TEXT, owner TEXT, logo TEXT, status TEXT DEFAULT 'active')`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, storeId TEXT, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, thumbnail TEXT, encryptedPayload TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, senderPic TEXT, message TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, secretKey TEXT, eccSignature TEXT, is_used INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, sender_name TEXT, amount INTEGER, status TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, amount INTEGER, status TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, targetStore TEXT)`);
});

// 🚀 2단계 로그인 로직 (회원 여부만 판단, 덮어쓰기 원천 차단)
app.post('/api/auth/verify', (req, res) => {
    db.get(`SELECT * FROM users WHERE name = ?`, [req.body.name], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            if (row.password === req.body.password) res.json({ exists: true, user: row });
            else res.status(401).json({ exists: true, error: "비밀번호가 일치하지 않습니다." });
        } else {
            res.json({ exists: false });
        }
    });
});

// 신규 회원 등록 (10,000원 보너스 지급)
app.post('/api/auth/register', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, 10000)`, [name, password, bank, account], (err) => {
        if (err) return res.status(500).json({ error: "회원 가입 처리 오류" });
        res.json({ name, password, bank, account, balance: 10000, profilePic: null });
    });
});

// 🚀 프로필 수정 (비밀번호 변경 포함)
app.post('/api/user/update', (req, res) => {
    db.run(`UPDATE users SET password = ?, bank = ?, account = ?, profilePic = ? WHERE name = ?`, 
        [req.body.password, req.body.bank, req.body.account, req.body.profilePic, req.body.name], () => res.json({success: true}));
});
app.get('/api/users/:name', (req, res) => { db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => res.json(row || { balance: 0 })); });

app.post('/api/friend/add', (req, res) => {
    const { userName, friendName } = req.body;
    db.get(`SELECT name FROM users WHERE name = ?`, [friendName], (err, row) => {
        if(!row) return res.status(404).json({ error: "존재하지 않는 회원 식별자입니다." });
        db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [userName, friendName], () => {
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [friendName, userName], () => res.json({ success: true }));
        });
    });
});
app.get('/api/friends/:userName', (req, res) => { db.all(`SELECT u.name, u.profilePic FROM friends f JOIN users u ON f.friendName = u.name WHERE f.userName = ?`, [req.params.userName], (err, rows) => { res.json(rows || []); }); });

app.post('/api/deposit/request', (req, res) => {
    db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date) VALUES (?, ?, ?, '대기', ?)`, [req.body.userName, req.body.senderName, Number(req.body.amount)||0, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); });
});

app.post('/api/withdraw/request', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.serialize(() => {
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.name]);
        db.run(`INSERT INTO withdrawals (name, amount, status, date) VALUES (?, ?, '대기', ?)`, [req.body.name, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
    });
});

app.get('/api/admin/actions', (req, res) => {
    db.all(`SELECT * FROM deposits WHERE status = '대기'`, [], (err, deps) => {
        db.all(`SELECT w.*, u.bank, u.account FROM withdrawals w JOIN users u ON w.name = u.name WHERE w.status = '대기'`, [], (err2, wds) => {
            res.json({ deposits: deps || [], withdrawals: wds || [] });
        });
    });
});

app.post('/api/admin/approve', (req, res) => {
    const { type, id, userName } = req.body; const amount = Number(req.body.amount) || 0;
    if(type === 'deposit_direct') {
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, userName]);
            db.run(`UPDATE deposits SET status = '승인_증액' WHERE id = ?`, [id], () => res.json({ success: true }));
        });
    } else if (type === 'withdraw') {
        db.run(`UPDATE withdrawals SET status = '승인출금완료' WHERE id = ?`, [id], () => res.json({ success: true }));
    }
});

app.post('/api/transfer', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.sender], (err, sRow) => {
        if (!sRow || sRow.balance < amount) return res.status(400).json({ error: "원장 가용 자산이 부족합니다." });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.sender]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.receiver]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date) VALUES (?, ?, ?, ?)`, [req.body.sender, req.body.receiver, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
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
function verifyECCInverseSignature(checkId, secretKey, amount, signature) {
    try {
        const hash = crypto.createHash('sha256').update(`${checkId}:${secretKey}:${amount}`).digest('hex');
        let inverseHex = ''; for (let i=0; i<hash.length; i++) inverseHex += (15 - parseInt(hash[i], 16)).toString(16);
        const verify = crypto.createVerify('SHA256'); verify.update(inverseHex); return verify.verify(publicKey, signature, 'hex');
    } catch(e){return false;}
}

app.post('/api/check/issue', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "가용 발행 한도를 초과했습니다." });
        const checkId = 'META_QR_' + Date.now(); const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
        const signature = generateECCInverseSignature(checkId, secretKey, amount); const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`, [checkId, amount, req.body.issuer, secretKey, signature, date]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [req.body.issuer, 'Earth(Root)', '보안 수표 발행', amount, date], () => res.json({ success: true, checkId, secretKey, signature }));
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId, secretKey, signature } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`; let params = [checkId];
    if (secretKey && !checkId) { query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`; params = [secretKey]; }
    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "이미 회수 완료된 핀 번호입니다." });
        if (signature && !verifyECCInverseSignature(row.id, row.secretKey, row.amount, signature)) return res.status(401).json({ error: "무결성 서명 파괴 (위조)" });
        const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [row.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, ['Earth(Root)', redeemer, '보안 수표 환원 충전', row.amount, date], () => res.json({ success: true, amount: row.amount }));
        });
    });
});

app.post('/api/store/create', (req, res) => { db.run(`INSERT INTO stores (id, name, owner, logo, status) VALUES (?, ?, ?, ?, 'active')`, ['STR_' + Date.now(), req.body.name, req.body.owner, req.body.logo], () => res.json({ success: true })); });
app.get('/api/stores/owned/:owner', (req, res) => { db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => res.json(rows || [])); });
app.post('/api/store/status', (req, res) => { db.run(`UPDATE stores SET status = ? WHERE id = ?`, [req.body.status, req.body.id], () => res.json({ success: true })); });
app.get('/api/stores/active', (req, res) => { db.all(`SELECT * FROM stores WHERE status = 'active'`, [], (err, rows) => res.json(rows || [])); });

app.post('/api/products/encrypt-build', (req, res) => {
    db.run(`INSERT INTO products (id, storeId, type, name, description, price, seller, thumbnail, encryptedPayload) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?)`, 
        ['PRD_' + Date.now(), req.body.storeId, req.body.name, req.body.description, Number(req.body.price)||0, req.body.seller, req.body.thumbnail, req.body.encryptedPayload], () => res.json({ success: true }));
});
app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/products/active', (req, res) => { db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' ORDER BY p.id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => res.json(row || {})); });
app.post('/api/product/edit', (req, res) => { db.run(`UPDATE products SET name = ?, price = ?, description = ? WHERE id = ?`, [req.body.name, Number(req.body.price)||0, req.body.description, req.body.id], () => res.json({ success: true })); });

// 🚀 어드민 강제 삭제 권한 API
app.post('/api/admin/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });
app.post('/api/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });

app.post('/api/buy', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "원장 자산 잔액 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [req.body.buyer, req.body.seller, req.body.productName, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
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
        const txs = await new Promise(r => db.all(`SELECT * FROM transactions WHERE buyer=? OR seller=?`, [name, name], (e, rows) => r(rows||[])));
        const tfs = await new Promise(r => db.all(`SELECT * FROM transfers WHERE sender=? OR receiver=?`, [name, name], (e, rows) => r(rows||[])));
        const dps = await new Promise(r => db.all(`SELECT * FROM deposits WHERE user_name=?`, [name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));
        
        let history = [];
        txs.forEach(t => history.push({ type: t.buyer === name ? '자산 구매' : '자산 판매', date: t.date, amount: t.amount, productName: t.productName, seller: t.buyer === name ? t.seller : t.buyer }));
        tfs.forEach(t => history.push({ type: t.sender === name ? '송금 (출금)' : '송금 (입금)', date: t.date, amount: t.amount, seller: t.receiver || t.sender }));
        dps.forEach(d => history.push({ type: `입금 신청 (${d.status})`, date: d.date, amount: d.amount, seller: 'Earth(Root)' }));
        wds.forEach(w => history.push({ type: `출금 집행 완료`, date: w.date, amount: w.amount, seller: '지정 등록 계좌' }));
        history.sort((a,b) => new Date(b.date) - new Date(a.date)); res.json(history);
    } catch(e) { res.json([]); }
});

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => { 
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date) VALUES (?, ?, ?, ?, ?)`, [data.roomId, data.sender, data.senderPic, data.message, new Date().toLocaleString('ko-KR')], () => { io.emit('receive_message', data); }); 
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[EARTH SYSTEM V7 PERFECT] BOUND ON PORT ${PORT}`); });
