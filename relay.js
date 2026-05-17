const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// 1. 엔터프라이즈 레벨 CORS 커널 완전 개방
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
}));

app.use(express.json({ limit: '1000mb' }));
const server = http.createServer(app);

// 2. 소켓 웹 엔진 정격 인프라 맵핑
const io = new Server(server, { 
    cors: { origin: "*", methods: ["GET", "POST"] },
    transports: ['websocket', 'polling']
});

const PORT = 4000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

const db = new sqlite3.Database(path.join(__dirname, 'commerce.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, filePath TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, message TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS favorites (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, productId TEXT)`);
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const safeName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, Date.now() + '_' + safeName);
    }
});
const upload = multer({ storage });

// --- [API] 크립토 뱅킹 및 인증 레이어 ---
app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (err) return res.status(500).json({ error: "DB 에러" });
        if (row) {
            if (row.password !== password) return res.status(401).json({ error: "패스워드 불일치" });
            return res.json(row);
        } else {
            if (!bank || !account || !password) return res.status(400).json({ error: "인증 명세 누락" });
            const initialBalance = 1000000;
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, ?)`, 
                [name, password, bank, account, initialBalance], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                return res.json({ name, bank, account, balance: initialBalance });
            });
        }
    });
});

app.get('/api/users/:name', (req, res) => {
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => { res.json(row || { balance: 0 }); });
});

// --- [API] 상점 즐겨찾기 엔진 ---
app.post('/api/favorites', (req, res) => {
    const { userName, productId } = req.body;
    db.get(`SELECT * FROM favorites WHERE userName=? AND productId=?`, [userName, productId], (err, row) => {
        if(row) {
            db.run(`DELETE FROM favorites WHERE userName=? AND productId=?`, [userName, productId], () => res.json({status:"removed"}));
        } else {
            db.run(`INSERT INTO favorites (userName, productId) VALUES (?, ?)`, [userName, productId], () => res.json({status:"added"}));
        }
    });
});

app.get('/api/favorites/:userName', (req, res) => {
    db.all(`SELECT productId FROM favorites WHERE userName=?`, [req.params.userName], (err, rows) => {
        res.json(rows ? rows.map(r => r.productId) : []);
    });
});

// --- [API] 무역 자산 마운트 라우터 ---
app.get('/api/products', (req, res) => {
    db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => { res.json(rows || []); });
});

app.post('/api/products', upload.single('file'), (req, res) => {
    const { id, type, name, description, price, seller } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : '';
    db.run(`INSERT INTO products (id, type, name, description, price, seller, filePath) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, type, name, description, parseInt(price), seller, filePath], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, filePath });
    });
});

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    db.get(`SELECT filePath FROM products WHERE id = ?`, [productId], (err, prod) => {
        const fileLink = prod ? prod.filePath : '';
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, date]);
            db.run('COMMIT', (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, fileLink });
            });
        });
    });
});

app.get('/api/transactions/:name', (req, res) => {
    db.all(`SELECT * FROM transactions WHERE buyer = ? OR seller = ? ORDER BY id DESC`, [req.params.name, req.params.name], (err, rows) => { res.json(rows || []); });
});

// --- [API] 1:1 세널 독립 디코더 라우터 ---
app.get('/api/chat/:roomId', (req, res) => {
    db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => {
        res.json(rows || []);
    });
});

// 실시간 패킷 정렬 레이어
io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => {
        const date = new Date().toLocaleString('ko-KR');
        db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`,
            [data.roomId, data.sender, data.message, date], (err) => {
                if (!err) {
                    io.to(data.roomId).emit('receive_message', { ...data, date });
                }
            });
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Core Integration Base Engine Stabilized. Port ${PORT}`);
});
