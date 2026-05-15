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

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(__dirname));

// 📂 업로드 및 데이터 폴더 설정
const DATA_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
app.use('/uploads', express.static(DATA_DIR));

// 💾 통합 SQLite DB (금융 + 환자 + 거래)
const db = new sqlite3.Database(path.join(__dirname, 'oyp_integrated.db'));
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, usd REAL, hmj REAL, mb REAL, history TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS data_vault (fileId TEXT PRIMARY KEY, uploaderId TEXT, filename TEXT, filepath TEXT, sizeMB REAL, Ad REAL, Bd REAL)`);
    db.run(`CREATE TABLE IF NOT EXISTS trade_market (tradeId TEXT PRIMARY KEY, sellerId TEXT, fileId TEXT, priceHMJ REAL, status TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS ownership (fileId TEXT, ownerId TEXT, PRIMARY KEY(fileId, ownerId))`);
});

const upload = multer({ storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, DATA_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
})});

// 루트 접속 시 통합 플랫폼 송출
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// [1] 통합 로그인 및 자산 조회
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    db.get('SELECT * FROM accounts WHERE id = ?', [acc], (err, row) => {
        if (!row) {
            const initHistory = JSON.stringify([{ type: 'WELCOME', detail: 'OYP 노드 접속 보너스', time: new Date().toLocaleString() }]);
            db.run(`INSERT INTO accounts VALUES (?, 100.0, 10.0, 0.0, ?)`, [acc, initHistory], () => {
                res.json({ id: acc, usd: 100, hmj: 10, mb: 0, history: JSON.parse(initHistory) });
            });
        } else { row.history = JSON.parse(row.history); res.json(row); }
    });
});

// [2] 데이터 관리: MARS-1 암호화 업로드
app.post('/api/data/upload', upload.single('file'), (req, res) => {
    const { uploaderId, Ad, Bd } = req.body;
    const fileId = 'FILE_' + Math.random().toString(36).substring(2, 9).toUpperCase();
    const sizeMB = (req.file.size / (1024 * 1024)).toFixed(2);
    const filepath = `/uploads/${req.file.filename}`;

    db.serialize(() => {
        db.run(`INSERT INTO data_vault VALUES (?, ?, ?, ?, ?, ?, ?)`, [fileId, uploaderId, req.file.originalname, filepath, sizeMB, Ad, Bd]);
        db.run(`INSERT INTO ownership VALUES (?, ?)`, [fileId, uploaderId]);
        res.json({ success: true, fileId });
    });
});

app.get('/api/data/myfiles/:accountId', (req, res) => {
    db.all(`SELECT v.* FROM data_vault v JOIN ownership o ON v.fileId = o.fileId WHERE o.ownerId = ?`, [req.params.accountId], (err, rows) => res.json(rows));
});

// [3] 데이터 거래 및 소켓 통신 (생략된 로직은 통합본 유지)
io.on('connection', (socket) => {
    socket.on('join', (id) => socket.join(id));
    socket.on('chat', (data) => io.emit('receive_chat', data));
});

server.listen(4000, '0.0.0.0', () => console.log('🚀 OYP Unified Node Online: Port 4000'));
