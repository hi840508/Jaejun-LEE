const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE"], allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"] }));

// [방어 코드] 잘못된 JSON 데이터가 들어와도 서버가 죽지 않도록 방어하는 미들웨어
app.use(express.json({ limit: '500mb' }));
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: "잘못된 네트워크 패킷입니다." });
    }
    next();
});
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, transports: ['websocket', 'polling'] });
const PORT = 4000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use('/uploads', express.static(UPLOAD_DIR, {
    setHeaders: (res, path, stat) => {
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    }
}));

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// [DB 자가치유 스크립트] 파일 삭제 없이 알아서 누락된 구조를 추가합니다.
const db = new sqlite3.Database(path.join(__dirname, 'commerce.db'));
db.serialize(() => {
    // 1. 기본 뼈대 창설
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, filePath TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, message TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS favorite_products (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, productId TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, storeName TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, is_used INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT)`);
    
    // 2. 구버전 DB일 경우 누락된 컬럼(password, bank, account) 자동 업데이트 (에러 무시)
    db.run(`ALTER TABLE users ADD COLUMN password TEXT`, (err) => {});
    db.run(`ALTER TABLE users ADD COLUMN bank TEXT`, (err) => {});
    db.run(`ALTER TABLE users ADD COLUMN account TEXT`, (err) => {});
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const safeName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, Date.now() + '_' + safeName);
    }
});
const upload = multer({ storage });

app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    if (!name || !password) return res.status(400).json({ error: "이름과 비밀번호가 누락되었습니다." });

    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (err) return res.status(500).json({ error: "DB 동기화 에러. 잠시 후 다시 시도하세요." });
        if (row) {
            // 구버전 계정 호환성 유지
            if (row.password && row.password !== password) return res.status(401).json({ error: "패스워드 불일치" });
            return res.json({ name: row.name, bank: row.bank || bank, account: row.account || account, balance: row.balance });
        } else {
            const initialBalance = 1000000;
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, ?)`, 
                [name, password, bank || '등록은행', account || '000-000', initialBalance], (err) => {
                if (err) return res.status(500).json({ error: "계정 생성 중 오류가 발생했습니다." });
                return res.json({ name, bank: bank || '등록은행', account: account || '000-000', balance: initialBalance });
            });
        }
    });
});

app.get('/api/users/:name', (req, res) => {
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => { res.json(row || { balance: 0 }); });
});

app.post('/api/transfer', (req, res) => {
    const { sender, receiver, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [sender], (err, senderRow) => {
        if (!senderRow || senderRow.balance < amount) return res.status(400).json({ error: "잔액 부족" });
        db.get(`SELECT * FROM users WHERE name = ?`, [receiver], (err, receiverRow) => {
            if (!receiverRow) return res.status(404).json({ error: "존재하지 않는 수신자입니다." });
            const date = new Date().toLocaleString('ko-KR');
            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, sender]);
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, receiver]);
                db.run(`INSERT INTO transfers (sender, receiver, amount, date) VALUES (?, ?, ?, ?)`, [sender, receiver, amount, date]);
                db.run('COMMIT', (err) => {
                    if (err) return res.status(500).json({ error: "송금 처리 실패" });
                    res.json({ success: true });
                });
            });
        });
    });
});

app.post('/api/check/issue', (req, res) => {
    const { issuer, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "잔액이 부족합니다." });
        const checkId = 'QRCHK_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
        const date = new Date().toLocaleString('ko-KR');
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, is_used, date) VALUES (?, ?, ?, 0, ?)`, [checkId, amount, issuer, date]);
            db.run('COMMIT', (err) => { res.json({ success: true, checkId }); });
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId } = req.body;
    db.get(`SELECT * FROM qr_checks WHERE id = ?`, [checkId], (err, row) => {
        if (err) return res.status(500).json({ error: "DB 연결 에러" });
        if (!row) return res.status(404).json({ error: "유효하지 않은 가짜 수표입니다." });
        if (row.is_used === 1) return res.status(400).json({ error: "이미 누군가 사용한 수표입니다." });
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [checkId]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            db.run('COMMIT', (err) => { res.json({ success: true, amount: row.amount }); });
        });
    });
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => { res.json(rows || []); }); });
app.get('/api/stores', (req, res) => { db.all(`SELECT DISTINCT seller FROM products`, [], (err, rows) => { res.json(rows ? rows.map(r => r.seller) : []); }); });

app.post('/api/products/digital', upload.array('files'), (req, res) => {
    const { type, name, description, price, seller } = req.body;
    const filePath = req.files && req.files.length > 0 ? `/uploads/${req.files[0].filename}` : '';
    db.run(`INSERT INTO products (id, type, name, description, price, seller, filePath) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ['PRD_' + Date.now(), type, name, description, parseInt(price), seller, filePath], (err) => { res.json({ success: true }); });
});

app.post('/api/products/physical', upload.single('image'), (req, res) => {
    const { type, name, description, price, seller } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : '';
    db.run(`INSERT INTO products (id, type, name, description, price, seller, filePath) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ['PRD_' + Date.now(), type, name, description, parseInt(price), seller, filePath], (err) => { res.json({ success: true }); });
});

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "자산 한도 초과" });
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, date]);
            db.run('COMMIT', (err) => { res.json({ success: true }); });
        });
    });
});

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        const transactions = await new Promise((resolve) => { db.all(`SELECT * FROM transactions WHERE buyer = ? OR seller = ?`, [name, name], (err, rows) => resolve(rows || [])); });
        const transfers = await new Promise((resolve) => { db.all(`SELECT * FROM transfers WHERE sender = ? OR receiver = ?`, [name, name], (err, rows) => resolve(rows || [])); });
        const qrChecks = await new Promise((resolve) => { db.all(`SELECT * FROM qr_checks WHERE issuer = ?`, [name], (err, rows) => resolve(rows || [])); });
        
        const history = [];
        transactions.forEach(r => history.push({ type: 'asset', date: r.date, buyer: r.buyer, seller: r.seller, productName: r.productName, amount: r.amount }));
        transfers.forEach(r => history.push({ type: 'transfer', date: r.date, sender: r.sender, receiver: r.receiver, amount: r.amount }));
        qrChecks.forEach(r => history.push({ type: 'check_issue', date: r.date, amount: r.amount }));
        
        history.sort((a, b) => new Date(b.date) - new Date(a.date));
        res.json(history);
    } catch(e) { res.status(500).json([]); }
});

app.post('/api/favorites/store', (req, res) => {
    const { userName, storeName } = req.body;
    db.get(`SELECT * FROM favorite_stores WHERE userName=? AND storeName=?`, [userName, storeName], (err, row) => {
        if(row) { db.run(`DELETE FROM favorite_stores WHERE userName=? AND storeName=?`, [userName, storeName], () => res.json({status:"removed"})); } 
        else { db.run(`INSERT INTO favorite_stores (userName, storeName) VALUES (?, ?)`, [userName, storeName], () => res.json({status:"added"})); }
    });
});

app.get('/api/favorites/:userName', (req, res) => {
    db.all(`SELECT productId FROM favorite_products WHERE userName=?`, [req.params.userName], (err, pRows) => {
        db.all(`SELECT storeName FROM favorite_stores WHERE userName=?`, [req.params.userName], (err, sRows) => {
            res.json({ products: pRows ? pRows.map(r => r.productId) : [], stores: sRows ? sRows.map(r => r.storeName) : [] });
        });
    });
});

app.get('/api/chat/:roomId', (req, res) => { db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => { res.json(rows || []); }); });

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => {
        const date = new Date().toLocaleString('ko-KR');
        db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`, [data.roomId, data.sender, data.message, date], () => { io.to(data.roomId).emit('receive_message', { ...data, date }); });
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`Core System bound on port ${PORT}`); });
