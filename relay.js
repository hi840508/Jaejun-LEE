const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// ⭐ CORS 개방: 프론트엔드에서 API 요청을 보낼 때 차단되지 않도록 모든 출처 허용
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE"] }));
app.use(express.json({ limit: '500mb' })); // 대용량 파일 전송을 위해 용량 확대
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(express.static(__dirname));

const server = http.createServer(app);

// ⭐ Socket.io CORS 설정: 실시간 채팅 연결을 허용
const io = new Server(server, { 
    cors: { 
        origin: "*", 
        methods: ["GET", "POST"] 
    },
    transports: ['websocket', 'polling'] 
});

const PORT = process.env.PORT || 4000;

// 실제 파일이 저장될 폴더 생성
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

// 파일 업로드 (Multer)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        // 한글 깨짐 방지 및 고유 파일명 생성
        const safeName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, Date.now() + '_' + safeName);
    }
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

// 상품 등록 시 파일 업로드 처리
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
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ success: false, error: "잔액이 부족합니다." });
        
        // 상품의 파일 경로 가져오기
        db.get(`SELECT filePath FROM products WHERE id = ?`, [productId], (err, prod) => {
            const fileLink = prod ? prod.filePath : '';
            
            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
                db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
                db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, date]);
                db.run('COMMIT', (err) => {
                    if (err) return res.status(500).json({ success: false, error: err.message });
                    res.json({ success: true, fileLink });
                });
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

server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ [운영 모드] 백엔드 서버가 포트 ${PORT}에서 실행 중입니다.`);
});
