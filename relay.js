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

const PORT = 4000; // 통합 운영 포트

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(__dirname));

// 📂 업로드 데이터 폴더 자동 생성
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// 💾 통합 SQLite DB (계정/환자/거래/소유권)
const db = new sqlite3.Database(path.join(__dirname, 'oyp_integrated.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, usd REAL, hmj REAL, mb REAL, history TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS data_vault (fileId TEXT PRIMARY KEY, uploaderId TEXT, filename TEXT, filepath TEXT, sizeMB REAL, Ad REAL, Bd REAL)`);
    db.run(`CREATE TABLE IF NOT EXISTS trade_market (tradeId TEXT PRIMARY KEY, sellerId TEXT, fileId TEXT, priceHMJ REAL, status TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS ownership (fileId TEXT, ownerId TEXT, PRIMARY KEY(fileId, ownerId))`);
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

// ⭐ 루트 접속 시 통합 UI(index.html) 서빙
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// [1] 통합 로그인 및 자산 관리 (MARS BANK 로직 포함)
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    db.get('SELECT * FROM accounts WHERE id = ?', [acc], (err, row) => {
        if (!row) {
            const initHist = JSON.stringify([{ type: 'WELCOME', detail: 'OYP 노드 접속 보너스', time: new Date().toLocaleString() }]);
            db.run(`INSERT INTO accounts VALUES (?, 100.0, 10.0, 0.0, ?)`, [acc, initHist], () => {
                res.json({ id: acc, usd: 100, hmj: 10, mb: 0, history: JSON.parse(initHist) });
            });
        } else { row.history = JSON.parse(row.history); res.json(row); }
    });
});

// [2] MARS-1 암호화 데이터 업로드 (데이터 관리)
app.post('/api/data/upload', upload.single('file'), (req, res) => {
    const { uploaderId, Ad, Bd } = req.body;
    const fileId = 'FILE_' + Math.random().toString(36).substring(2, 10).toUpperCase();
    const sizeMB = (req.file.size / (1024 * 1024)).toFixed(2);
    const filepath = `/uploads/${req.file.filename}`;

    db.serialize(() => {
        db.run(`INSERT INTO data_vault VALUES (?, ?, ?, ?, ?, ?, ?)`, [fileId, uploaderId, req.file.originalname, filepath, sizeMB, Ad, Bd]);
        db.run(`INSERT INTO ownership VALUES (?, ?)`, [fileId, uploaderId]);
        db.run(`UPDATE accounts SET mb = mb + ? WHERE id = ?`, [sizeMB, uploaderId], () => {
            res.json({ success: true, fileId });
        });
    });
});

// [3] 내 소유 데이터 리스트 조회
app.get('/api/data/myfiles/:accountId', (req, res) => {
    db.all(`SELECT v.* FROM data_vault v JOIN ownership o ON v.fileId = o.fileId WHERE o.ownerId = ?`, [req.params.accountId], (err, rows) => {
        res.json(rows || []);
    });
});

// [4] 데이터 거래 마켓 API
app.get('/api/trade/market', (req, res) => {
    db.all(`SELECT t.*, v.filename FROM trade_market t JOIN data_vault v ON t.fileId = v.fileId WHERE t.status = 'OPEN'`, [], (err, rows) => res.json(rows || []));
});

app.post('/api/trade/list', (req, res) => {
    const { sellerId, fileId, priceHMJ } = req.body;
    const tradeId = 'TRD_' + Date.now();
    db.run(`INSERT INTO trade_market VALUES (?, ?, ?, ?, 'OPEN')`, [tradeId, sellerId, fileId, priceHMJ], () => res.json({ success: true }));
});

// [5] 자산 송금/수취 티켓 (기존 릴레이 로직 유지)
const ESCROW = new Map();
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount } = req.body;
    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    ESCROW.set(code, { assetType, amount: parseFloat(amount), senderId });
    res.json({ ticketCode: code });
});

// [6] 실시간 통신 (Socket.io)
io.on('connection', (socket) => {
    socket.on('join', (id) => socket.join(id));
    socket.on('chat', (data) => io.emit('receive_chat', data));
});

server.listen(PORT, '0.0.0.0', () => console.log(`🚀 OYP Integrated Platform Online: Port ${PORT}`));
