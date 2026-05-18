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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = 4000;

const db = new sqlite3.Database(path.join(__dirname, 'commerce_master_social.db'));

db.serialize(() => {
    // profilePic 컬럼 지원
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
});

app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (row) {
            if (row.password !== password) return res.status(401).json({ error: "비밀번호 오류" });
            return res.json(row);
        } else {
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, 10000)`, [name, password, bank, account], () => {
                res.json({ name, bank, account, balance: 10000, profilePic: null });
            });
        }
    });
});

app.post('/api/user/profile', (req, res) => {
    db.run(`UPDATE users SET profilePic = ? WHERE name = ?`, [req.body.profilePic, req.body.name], () => res.json({success: true}));
});

app.get('/api/users/:name', (req, res) => { db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => res.json(row || { balance: 0 })); });

// --- 소셜 친구 시스템 ---
app.post('/api/friend/add', (req, res) => {
    const { userName, friendName } = req.body;
    db.get(`SELECT name FROM users WHERE name = ?`, [friendName], (err, row) => {
        if(!row) return res.status(404).json({ error: "존재하지 않는 사용자입니다." });
        db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [userName, friendName]);
        db.run(`INSERT OR IGNORE INTO friends (userName, friendName) VALUES (?, ?)`, [friendName, userName], () => res.json({success:true}));
    });
});
app.get('/api/friends/:userName', (req, res) => {
    db.all(`SELECT u.name, u.profilePic FROM friends f JOIN users u ON f.friendName = u.name WHERE f.userName = ?`, [req.params.userName], (err, rows) => {
        res.json(rows || []);
    });
});

// --- 출금 및 입금 통합 (어드민 패널) ---
app.post('/api/deposit/request', (req, res) => {
    db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date) VALUES (?, ?, ?, '대기', ?)`, [req.body.userName, req.body.senderName, req.body.amount, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); });
});
app.post('/api/withdraw/request', (req, res) => {
    db.serialize(() => {
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [req.body.amount, req.body.name]);
        db.run(`INSERT INTO withdrawals (name, amount, status, date) VALUES (?, ?, '대기', ?)`, [req.body.name, req.body.amount, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); });
    });
});

app.get('/api/admin/actions', (req, res) => {
    db.all(`SELECT * FROM deposits WHERE status = '대기'`, [], (err, deps) => {
        db.all(`SELECT w.*, u.bank, u.account FROM withdrawals w JOIN users u ON w.name = u.name WHERE w.status = '대기'`, [], (err, wds) => {
            res.json({ deposits: deps || [], withdrawals: wds || [] });
        });
    });
});

app.post('/api/admin/approve', (req, res) => {
    const { type, id, userName, amount } = req.body;
    if(type === 'deposit') {
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, userName]);
            db.run(`UPDATE deposits SET status = '승인완료' WHERE id = ?`, [id]);
            res.json({ success: true });
        });
    } else {
        db.run(`UPDATE withdrawals SET status = '승인완료' WHERE id = ?`, [id], () => res.json({ success: true }));
    }
});

// --- 송금 시스템 (채팅방 내 송금 지원) ---
app.post('/api/transfer', (req, res) => {
    const { sender, receiver, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [sender], (err, sRow) => {
        if (!sRow || sRow.balance < amount) return res.status(400).json({ error: "잔액 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, sender]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, receiver]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date) VALUES (?, ?, ?, ?)`, [sender, receiver, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
        });
    });
});

// --- 커머스 API 생략 (이전과 동일하게 Products, Buy 동작) ---
app.post('/api/store/create', (req, res) => {
    const { name, owner, logo } = req.body; const storeId = 'STR_' + Date.now();
    db.run(`INSERT INTO stores (id, name, owner, logo, status) VALUES (?, ?, ?, ?, 'active')`, [storeId, name, owner, logo], () => res.json({ success: true }));
});
app.get('/api/stores/owned/:owner', (req, res) => { db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => res.json(rows || [])); });
app.get('/api/stores/active', (req, res) => { db.all(`SELECT * FROM stores WHERE status = 'active'`, [], (err, rows) => res.json(rows || [])); });

app.post('/api/products/encrypt-build', (req, res) => {
    const { name, price, seller, storeId, description, thumbnail, encryptedPayload } = req.body;
    const pid = 'PRD_' + Date.now();
    db.run(`INSERT INTO products (id, storeId, type, name, description, price, seller, thumbnail, encryptedPayload) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?)`, [pid, storeId, name, description, price, seller, thumbnail, encryptedPayload], () => { res.json({ success: true }); });
});
app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/products/active', (req, res) => { db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' ORDER BY p.id DESC`, [], (err, rows) => res.json(rows || [])); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => res.json(row || {})); });

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "자산 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, new Date().toLocaleString('ko-KR')], () => res.json({ success: true }));
        });
    });
});

app.get('/api/chat/:roomId', (req, res) => { db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => res.json(rows || [])); });

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        const txs = await new Promise(r => db.all(`SELECT * FROM transactions WHERE buyer=? OR seller=?`, [name, name], (e, rows) => r(rows||[])));
        const tfs = await new Promise(r => db.all(`SELECT * FROM transfers WHERE sender=? OR receiver=?`, [name, name], (e, rows) => r(rows||[])));
        const dps = await new Promise(r => db.all(`SELECT * FROM deposits WHERE user_name=?`, [name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));
        
        let history = [];
        txs.forEach(t => history.push({ type: t.buyer === name ? '자산구매' : '자산판매', date: t.date, amount: t.amount, productName: t.productName, seller: t.seller }));
        tfs.forEach(t => history.push({ type: t.sender === name ? 'P2P송금출금' : 'P2P송금입금', date: t.date, amount: t.amount, seller: t.receiver || t.sender }));
        dps.forEach(d => history.push({ type: `입금요청(${d.status})`, date: d.date, amount: d.amount, seller: '어드민' }));
        wds.forEach(w => history.push({ type: `계좌출금(${w.status})`, date: w.date, amount: w.amount, seller: '내계좌' }));
        
        history.sort((a,b) => new Date(b.date) - new Date(a.date)); res.json(history);
    } catch(e) { res.json([]); }
});

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => { 
        db.run(`INSERT INTO chats (roomId, sender, senderPic, message, date) VALUES (?, ?, ?, ?, ?)`, [data.roomId, data.sender, data.senderPic, data.message, new Date().toLocaleString('ko-KR')], () => { 
            io.to(data.roomId).emit('receive_message', data); 
        }); 
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[GITHUB SYSTEM V3 SOCIAL] BOUND ON PORT ${PORT}`); });
