const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// 1. 글로벌 CORS 프로토콜 정격 개방 (브라우저 Mixed Content 보호 정책 우회)
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
}));

app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

// 2. HTTP 네이티브 인스턴스 명시적 생성 (바인딩 충돌 차단)
const server = http.createServer(app);

// 3. 웹소켓 독립 엔진 주입 및 폴링 덤프 트래킹 가동
const io = new Server(server, { 
    cors: { 
        origin: "*", 
        methods: ["GET", "POST"] 
    },
    transports: ['websocket', 'polling'] // HTTP 타임아웃 발생 시 폴링 엔진으로 동적 세션 유지
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
    db.run(`CREATE TABLE IF NOT EXISTS withdraws (id TEXT PRIMARY KEY, name TEXT, account TEXT, amount INTEGER, date TEXT)`);
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const safeName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, Date.now() + '_' + safeName);
    }
});
const upload = multer({ storage });

// --- [API] 뱅킹 및 인증 레이어 ---
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

// --- [API] 관리자(어드민) 전용 기능 ---
app.post('/api/admin/deposit', (req, res) => {
    const { targetName, amount } = req.body;
    db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, targetName], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: "존재하지 않는 유저입니다." });
        res.json({ success: true });
    });
});

app.post('/api/withdraw', (req, res) => {
    const { id, name, account, amount, date } = req.body;
    db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.run(`INSERT INTO withdraws (id, name, account, amount, date) VALUES (?, ?, ?, ?, ?)`,
            [id, name, account, amount, date], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true });
        });
    });
});

app.get('/api/admin/withdraws', (req, res) => {
    db.all(`SELECT * FROM withdraws ORDER BY date ASC`, [], (err, rows) => { res.json(rows || []); });
});

app.post('/api/admin/withdraw/approve', (req, res) => {
    const { id } = req.body;
    db.run(`DELETE FROM withdraws WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// --- [API] 상점 즐겨찾기 ---
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

// --- [API] 자산 등록 및 마켓 라우터 ---
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
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "자산 한도 초과" });
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
});

app.get('/api/transactions/:name', (req, res) => {
    db.all(`SELECT * FROM transactions WHERE buyer = ? OR seller = ? ORDER BY id DESC`, [req.params.name, req.params.name], (err, rows) => { res.json(rows || []); });
});

// 진성 고정 마스터 라우터 (404 예외 완벽 제거)
app.get('/api/chat/:roomId', (req, res) => {
    db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => {
        if (err) return res.status(500).json([]);
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

// 정격 서버 리슨 개시
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[REAL PRODUCTION] Core System bound successfully on port ${PORT}`);
});
