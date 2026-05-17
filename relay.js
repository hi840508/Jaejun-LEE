const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static(__dirname));

// 업로드 폴더 생성
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// DB 초기화
const db = new sqlite3.Database(path.join(__dirname, 'commerce.db'));

db.serialize(() => {
    // 사용자 테이블
    db.run(`CREATE TABLE IF NOT EXISTS users (
        name TEXT PRIMARY KEY, account TEXT, balance INTEGER
    )`);
    // 상품 테이블
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY, type TEXT, name TEXT, desc TEXT, price INTEGER, seller TEXT, filePath TEXT
    )`);
    // 거래 내역 테이블
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT
    )`);
    // 채팅 테이블 (상품 단위)
    db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roomId TEXT, productId TEXT, sender TEXT, message TEXT, date TEXT
    )`);
});

// 파일 업로드 설정
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

// --- [API] 인증 및 지갑 ---
app.post('/api/login', (req, res) => {
    const { name, account } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            // 기존 유저
            res.json(row);
        } else {
            // 신규 가입 (기본 잔액 1,000,000원 지급)
            const initialBalance = 1000000;
            db.run(`INSERT INTO users (name, account, balance) VALUES (?, ?, ?)`, [name, account, initialBalance], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ name, account, balance: initialBalance });
            });
        }
    });
});

app.get('/api/users/:name', (req, res) => {
    db.get(`SELECT * FROM users WHERE name = ?`, [req.params.name], (err, row) => {
        res.json(row || { balance: 0 });
    });
});

// --- [API] 상품 및 거래 ---
app.get('/api/products', (req, res) => {
    db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/products', upload.single('file'), (req, res) => {
    const { id, type, name, desc, price, seller } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : '';
    
    db.run(`INSERT INTO products (id, type, name, desc, price, seller, filePath) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, type, name, desc, parseInt(price), seller, filePath], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
    });
});

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    const date = new Date().toLocaleString('ko-KR');

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
        db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
        db.run(`INSERT INTO transactions (type, buyer, seller, productName, amount, date) VALUES ('buy', ?, ?, ?, ?, ?)`,
            [buyer, seller, productName, amount, date]);
        db.run('COMMIT', (err) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true });
        });
    });
});

app.get('/api/transactions/:name', (req, res) => {
    const name = req.params.name;
    db.all(`SELECT * FROM transactions WHERE buyer = ? OR seller = ? ORDER BY id DESC`, [name, name], (err, rows) => {
        res.json(rows || []);
    });
});

// --- [API] 채팅 내역 불러오기 ---
app.get('/api/chat/:roomId', (req, res) => {
    db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => {
        res.json(rows || []);
    });
});

// --- [소켓] 실시간 채팅 ---
io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => {
        socket.join(roomId);
    });

    socket.on('send_message', (data) => {
        const date = new Date().toLocaleString('ko-KR');
        // DB 저장
        db.run(`INSERT INTO chats (roomId, productId, sender, message, date) VALUES (?, ?, ?, ?, ?)`,
            [data.roomId, data.productId, data.sender, data.message, date], (err) => {
                if (!err) {
                    // 방에 있는 인원에게 브로드캐스트
                    io.to(data.roomId).emit('receive_message', { ...data, date });
                }
            });
    });
});

server.listen(PORT, '0.0.0.0', () => console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`));
