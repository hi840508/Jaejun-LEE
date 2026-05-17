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
// CORS 설정: 외부 IP(프론트엔드)에서 자유롭게 소켓 통신을 할 수 있게 열어줍니다.
const io = new Server(server, { cors: { origin: "*" } });

const PORT = 4000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// 업로드할 파일들을 저장할 폴더 생성
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// SQLite DB 세팅
const db = new sqlite3.Database(path.join(__dirname, 'commerce.db'));

db.serialize(() => {
    // 1. 유저 테이블 (이름, 비밀번호, 은행, 계좌번호)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER
    )`);
    // 2. 상품 테이블
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, filePath TEXT
    )`);
    // 3. 거래 내역 테이블
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT
    )`);
    // 4. 채팅 기록 테이블
    db.run(`CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roomId TEXT, sender TEXT, message TEXT, date TEXT
    )`);
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

// ==========================================
// [API] 인증 시스템 (로그인/회원가입)
// ==========================================
app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (err) return res.status(500).json({ error: "DB 연결 에러" });
        
        if (row) {
            // 이미 가입된 유저라면 비밀번호를 검증합니다.
            if (row.password !== password) {
                return res.status(401).json({ error: "비밀번호가 일치하지 않습니다." });
            }
            res.json(row);
        } else {
            // 신규 가입
            if (!bank || !account || !password) {
                return res.status(400).json({ error: "신규 가입 시 이름, 비밀번호, 은행, 계좌번호를 모두 입력해야 합니다." });
            }
            const initialBalance = 1000000; // 가입 축하금
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
        // 유저 정보가 없으면 잔액 0원 리턴 (JSON 파싱 에러 방지)
        res.json(row || { balance: 0 });
    });
});

// ==========================================
// [API] 상품 및 거래
// ==========================================
app.get('/api/products', (req, res) => {
    db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => {
        res.json(rows || []);
    });
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
            // 구매자 잔액 차감, 판매자 잔액 추가
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            // 거래 기록 남기기
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`,
                [buyer, seller, productName, amount, date]);
            db.run('COMMIT', (err) => {
                if (err) return res.status(500).json({ success: false, error: err.message });
                res.json({ success: true });
            });
        });
    });
});

app.get('/api/transactions/:name', (req, res) => {
    const name = req.params.name;
    db.all(`SELECT * FROM transactions WHERE buyer = ? OR seller = ? ORDER BY id DESC`, [name, name], (err, rows) => {
        res.json(rows || []);
    });
});

// ==========================================
// [API] 채팅 내역 불러오기 (⭐ 이전 404 에러의 원인 해결)
// ==========================================
app.get('/api/chat/:roomId', (req, res) => {
    const roomId = req.params.roomId;
    db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [roomId], (err, rows) => {
        if (err) {
            console.error("채팅 내역 불러오기 실패:", err);
            return res.json([]);
        }
        res.json(rows || []);
    });
});

// ==========================================
// [소켓] 실시간 채팅 통신
// ==========================================
io.on('connection', (socket) => {
    // 1. 클라이언트가 특정 상품 채팅방에 입장할 때
    socket.on('join_room', (roomId) => {
        socket.join(roomId);
    });

    // 2. 클라이언트가 메시지를 전송했을 때
    socket.on('send_message', (data) => {
        const date = new Date().toLocaleString('ko-KR');
        // DB에 채팅 기록 저장
        db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`,
            [data.roomId, data.sender, data.message, date], (err) => {
                if (!err) {
                    // 저장이 완료되면 해당 방(roomId)에 있는 모든 사람에게 메시지 뿌려줌
                    io.to(data.roomId).emit('receive_message', { ...data, date });
                } else {
                    console.error("메시지 저장 오류:", err);
                }
            });
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ [성공] 서버가 포트 ${PORT}에서 실행 중입니다.`);
    console.log(`✅ 브라우저 주소창에 http://54.180.125.166:4000/ 입력하여 접속하세요.`);
});
