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

// 📂 데이터 저장 경로 (EC2 환경)
const DATA_DIR = path.join(__dirname, 'RAY_Data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
app.use('/data', express.static(DATA_DIR));

// 💾 통합 DB (금융 장부 + 환자 데이터)
const db = new sqlite3.Database(path.join(__dirname, 'oyp_integrated.db'));
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, usd REAL, hmj REAL, mb REAL, history TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS patients (id TEXT PRIMARY KEY, name TEXT, chartNumber TEXT, gender TEXT, birthDate TEXT, history TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS data_vault (fileId TEXT PRIMARY KEY, uploaderId TEXT, filename TEXT, filepath TEXT, Ad REAL, Bd REAL)`);
});

const upload = multer({ storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, DATA_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
})});

// 루트 접속 시 통합 플랫폼(index.html) 서빙
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// [금융 API] 계정 조회 및 초기화
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    db.get('SELECT * FROM accounts WHERE id = ?', [acc], (err, row) => {
        if (!row) {
            const initHist = JSON.stringify([{ type: 'WELCOME', detail: 'OYP 가입 보너스', time: new Date().toLocaleString() }]);
            db.run(`INSERT INTO accounts VALUES (?, 100.0, 10.0, 0.0, ?)`, [acc, initHist], () => {
                res.json({ id: acc, usd: 100, hmj: 10, mb: 0, history: JSON.parse(initHist) });
            });
        } else { row.history = JSON.parse(row.history); res.json(row); }
    });
});

// [데이터 API] 암호화 업로드
app.post('/api/data/upload', upload.single('file'), (req, res) => {
    const { uploaderId, Ad, Bd } = req.body;
    const fileId = 'F_' + Math.random().toString(36).substring(2, 7).toUpperCase();
    const filepath = `/data/${req.file.filename}`;
    db.run(`INSERT INTO data_vault VALUES (?, ?, ?, ?, ?, ?)`, [fileId, uploaderId, req.file.originalname, filepath, Ad, Bd], () => {
        res.json({ success: true, fileId });
    });
});

// [통신] 실시간 소켓
io.on('connection', (socket) => {
    socket.on('join', (id) => socket.join(id));
    socket.on('chat', (data) => io.emit('receive_chat', data));
});

server.listen(4000, '0.0.0.0', () => console.log('🚀 OYP 통합 서버 가동 (Port 4000)'));
