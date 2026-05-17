const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// ⭐ [해결 포인트 1] Express CORS 완벽 개방
app.use(cors({ origin: "*", methods: ["GET", "POST"] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const server = http.createServer(app);

// ⭐ [해결 포인트 2] Socket.io CORS 완벽 개방 및 전송 규격 명시
const io = new Server(server, { 
    cors: { 
        origin: "*", 
        methods: ["GET", "POST"] 
    },
    transports: ['websocket', 'polling'] // 클라이언트가 어떤 방식으로든 무조건 연결되게 함
});

const PORT = 4000;

// 업로드 폴더 생성
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// DB 초기화
const db = new sqlite3.Database(path.join(__dirname, 'commerce.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, filePath TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, message TEXT, date TEXT)`);
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

// --- [API] 인증 ---
app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (err) return res.status(500).json({ error: "DB 연결 에러" });
        if (row) {
            if (row.password !== password) return res.status(401).json({ error: "비밀번호가 일치하지 않습니다." });
            res.json(row);
        } else {
            if (!bank || !account || !password) return res.status(400).json({ error: "신규 가입 시 정보를 모두 입력해야 합니다." });
            const initialBalance = 1000000;
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, ?)`, 
                [name, password, bank, account, initialBalance], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ name, bank, account, balance: initialBalance });
            });
        }
    });
});

app.get('/api/users/:name', (req, res) => {
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => {
        res.json(row || { balance: 0 });
    });
});

// --- [API] 상품 및 거래 ---
app.get('/api/products', (req, res) => {
    db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => { res.json(rows || []); });
});

app.post('/api/products', upload.single('file'), (req, res) => {
    const { id, type, name, description, price, seller } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : '';
    db.run(`INSERT INTO products (id, type, name, description, price, seller, filePath) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, type, name, description, parseInt(price), seller, filePath], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
    });
});

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ success: false, error: "잔액이 부족합니다." });
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, date]);
            db.run('COMMIT', (err) => {
                if (err) return res.status(500).json({ success: false, error: err.message });
                res.json({ success: true });
            });
        });
    });
});

app.get('/api/transactions/:name', (req, res) => {
    const name = req.params.name;
    db.all(`SELECT * FROM transactions WHERE buyer = ? OR seller = ? ORDER BY id DESC`, [name, name], (err, rows) => { res.json(rows || []); });
});

// --- [API] 채팅 내역 ---
app.get('/api/chat/:roomId', (req, res) => {
    const roomId = req.params.roomId;
    db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [roomId], (err, rows) => {
        if (err) return res.json([]);
        res.json(rows || []);
    });
});

// --- [소켓] 실시간 채팅 ---
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

// 서버 실행 구문 (app.listen이 아니라 반드시 server.listen으로 실행)
server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ OYP Meta Commerce Backend Running on Port ${PORT}`);
});
