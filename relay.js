const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const zlib = require('zlib');
const { Server } = require('socket.io');

const app = report = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = 4000;

const DB_PATH = '/home/ubuntu/earth_final_v8.sqlite';
const db = new sqlite3.Database(DB_PATH);

function initTables() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER, profilePic TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS friends (userName TEXT, friendName TEXT, UNIQUE(userName, friendName))`);
        db.run(`CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, name TEXT, owner TEXT, logo TEXT, status TEXT DEFAULT 'active')`);
        db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, storeId TEXT, type TEXT, name TEXT, description TEXT, price_stream INTEGER DEFAULT 0, price_original INTEGER DEFAULT 0, stream_time INTEGER DEFAULT 0, stream_unit TEXT DEFAULT 'd', seller TEXT, thumbnail TEXT, encryptedPayload TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productId TEXT, productName TEXT, amount INTEGER, purchaseType TEXT, rawDate TEXT, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, senderPic TEXT, message TEXT, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, secretKey TEXT, eccSignature TEXT, is_used INTEGER, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, sender_name TEXT, amount INTEGER, status TEXT, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, amount INTEGER, status TEXT, date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, targetStore TEXT)`);
    });
}
initTables();

app.post('/api/admin/db-reset', (req, res) => {
    db.serialize(() => {
        const tables = ['users', 'friends', 'stores', 'products', 'transactions', 'chats', 'qr_checks', 'transfers', 'deposits', 'withdrawals', 'favorite_stores'];
        tables.forEach(t => db.run(`DROP TABLE IF EXISTS ${t}`)); initTables(); res.json({ success: true });
    });
});

app.post('/api/auth/verify', (req, res) => {
    db.get(`SELECT * FROM users WHERE name = ?`, [req.body.name], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            if (row.password === req.body.password) res.json({ exists: true, user: row });
            else res.status(401).json({ exists: true, error: "비밀번호 불일치" });
        } else res.json({ exists: false });
    });
});

app.post('/api/auth/register', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, 10000)`, [name, password, bank, account], (err) => {
        if (err) return res.status(500).json({ error: "가입결함" }); res.json({ name, password, bank, account, balance: 10000, profilePic: null });
    });
});

app.post('/api/user/update', (req, res) => { db.run(`UPDATE users SET password = ?, bank = ?, account = ?, profilePic = ? WHERE name = ?`, [req.body.password, req.body.bank, req.body.account, req.body.profilePic, req.body.name], () => res.json({success: true})); });
app.get('/api/users/:name', (req, res) => { db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => res.json(row || { balance: 0 })); });

app.post('/api/friend/add', (req, res) => {
    const { userName, friendName } = req.body;
    db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [userName, friendName], () => {
        db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [friendName, userName], () => res.json({ success: true }));
    });
});
app.get('/api/friends/:userName', (req, res) => { db.all(`SELECT u.name, u.profilePic FROM friends f JOIN users u ON f.friendName = u.name WHERE f.userName = ?`, [req.params.userName], (err, rows) => res.json(rows || [])); });

app.get('/api/chat/active-rooms/:name', (req, res) => {
    const name = req.params.name;
    const query = `
        SELECT roomId, sender, message as lastMsg, date as lastDate,
        (SELECT profilePic FROM users WHERE name = (CASE WHEN sender = ? THEN REPLACE(roomId, 'room_msg_', '') ELSE sender END)) as partnerPic
        FROM chats 
        WHERE id IN (SELECT MAX(id) FROM chats WHERE roomId LIKE ? OR roomId LIKE ? GROUP BY roomId)
        ORDER BY id DESC`;
    db.all(query, [name, `%_${name}`, `${name}_%`], (err, rows) => {
        if(err) return res.status(500).json([]);
        let result = (rows || []).map(r => {
            let pName = r.roomId.replace('room_msg_', '').split('_').filter(n => n !== name)[0] || '이재준';
            return { roomId: r.roomId, partnerName: pName, lastMsg: r.lastMsg, lastDate: r.lastDate, partnerPic: r.partnerPic };
        });
        res.json(result);
    });
});

app.post('/api/deposit/request', (req, res) => { db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date) VALUES (?, ?, ?, '대기', ?)`, [req.body.userName, req.body.senderName, Number(req.body.amount)||0, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); }); });
app.post('/api/withdraw/request', (req, res) => { const amount = Number(req.body.amount) || 0; db.serialize(() => { db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.name]); db.run(`INSERT INTO withdrawals (name, amount, status, date) VALUES (?, ?, '대기', ?)`, [req.body.name, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true })); }); });

app.get('/api/admin/actions', (req, res) => { db.all(`SELECT * FROM deposits WHERE status = '대기'`, [], (err, deps) => { db.all(`SELECT w.*, u.bank, u.account FROM withdrawals w JOIN users u ON w.name = u.name WHERE w.status = '대기'`, [], (err2, wds) => { res.json({ deposits: deps || [], withdrawals: wds || [] }); }); }); });
app.post('/api/admin/approve', (req, res) => { const { type, id, userName } = req.body; const amount = Number(req.body.amount) || 0; if(type === 'deposit_direct') { db.serialize(() => { db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, userName]); db.run(`UPDATE deposits SET status = '승인_증액' WHERE id = ?`, [id], () => res.json({ success: true })); }); } else if (type === 'withdraw') { db.run(`UPDATE withdrawals SET status = '승인출금완료' WHERE id = ?`, [id], () => res.json({ success: true })); } });

app.post('/api/transfer', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.sender], (err, sRow) => {
        if (!sRow || sRow.balance < amount) return res.status(400).json({ error: "원장 자산 잔액 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.sender]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.receiver]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date) VALUES (?, ?, ?, ?)`, [req.body.sender, req.body.receiver, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
        });
    });
});

app.post('/api/store/close', (req, res) => { db.serialize(() => { db.run(`DELETE FROM products WHERE storeId = ? AND seller = ?`, [req.body.id, req.body.owner]); db.run(`DELETE FROM stores WHERE id = ? AND owner = ?`, [req.body.id, req.body.owner], () => res.json({ success: true })); }); });
app.post('/api/admin/store/close', (req, res) => { db.serialize(() => { db.run(`DELETE FROM products WHERE storeId = ?`, [req.body.id]); db.run(`DELETE FROM stores WHERE id = ?`, [req.body.id], () => res.json({ success: true })); }); });

app.post('/api/store/create', (req, res) => { db.run(`INSERT INTO stores (id, name, owner, logo, status) VALUES (?, ?, ?, ?, 'active')`, ['STR_' + Date.now(), req.body.name, req.body.owner, req.body.logo], () => res.json({ success: true })); });
app.get('/api/stores/owned/:owner', (req, res) => { db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => res.json(rows || [])); });
app.post('/api/store/status', (req, res) => { db.run(`UPDATE stores SET status = ? WHERE id = ?`, [req.body.status, req.body.id], () => res.json({ success: true })); });
app.get('/api/stores/active', (req, res) => { db.all(`SELECT * FROM stores WHERE status = 'active'`, [], (err, rows) => res.json(rows || [])); });

app.post('/api/products/encrypt-build', (req, res) => {
    const pid = 'PRD_' + Date.now();
    db.run(`INSERT INTO products (id, storeId, type, name, description, price_stream, price_original, stream_time, stream_unit, seller, thumbnail, encryptedPayload) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
        [pid, req.body.storeId, req.body.name, req.body.description, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, Number(req.body.stream_time)||0, req.body.stream_unit, req.body.seller, req.body.thumbnail, req.body.encryptedPayload], function() {
            res.json({ success: true, id: pid });
        });
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || [])); });
// 🚀 1:1 대화방 비밀매물(storeId가 room_msg_로 시작)은 마켓 비노출 강제 제한
app.get('/api/products/active', (req, res) => { db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' AND p.storeId NOT LIKE 'room_msg_%' ORDER BY p.id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => res.json(row || {})); });
app.post('/api/product/edit', (req, res) => { db.run(`UPDATE products SET name = ?, description = ?, stream_time = ?, stream_unit = ?, price_stream = ?, price_original = ? WHERE id = ?`, [req.body.name, req.body.description, Number(req.body.stream_time)||0, req.body.stream_unit, Number(req.body.price_stream)||0, Number(req.body.price_original)||0, req.body.id], () => res.json({ success: true })); });
app.post('/api/admin/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });
app.post('/api/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });

app.post('/api/buy', (req, res) => {
    const amount = Number(req.body.amount) || 0; const pType = req.body.purchaseType; const rawDate = new Date().toISOString();
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "원장 자산 잔액 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, req.body.seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productId, productName, amount, purchaseType, rawDate, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [req.body.buyer, req.body.seller, req.body.productId, req.body.productName, amount, pType, rawDate, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
        });
    });
});

// QR 회수 
app.post('/api/check/issue', (req, res) => {
    const amount = Number(req.body.amount) || 0;
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.body.issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "발행 한도 초과" });
        const checkId = 'META_QR_' + Date.now(); const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
        const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, req.body.issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, '', 0, ?)`, [checkId, amount, req.body.issuer, secretKey, date]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [req.body.issuer, 'Earth(Root)', '보안 수표 발행', amount, date], () => res.json({ success: true, checkId, secretKey }));
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId, secretKey } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`; let params = [checkId];
    if (secretKey && !checkId) { query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`; params = [secretKey]; }
    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "무효한 수표" });
        const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [row.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, ['Earth(Root)', redeemer, '보안 수표 충전 완료', row.amount, date], () => res.json({ success: true, amount: row.amount }));
        });
    });
});

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => { 
        // 🚀 실시간 친구 관계 동적 편입 (방 생성 원장)
        const users = data.roomId.replace('room_msg_', '').split('_');
        if(users.length === 2) {
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[0], users[1]]);
            db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [users[1], users[0]]);
        }
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date) VALUES (?, ?, ?, ?, ?)`, [data.roomId, data.sender, data.senderPic, data.message, new Date().toLocaleString('ko-KR')], () => { io.emit('receive_message', data); }); 
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[EARTH BRAND V9 PERFECT] BOUND ON PORT ${PORT}`); });
