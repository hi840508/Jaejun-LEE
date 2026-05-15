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

// 📂 데이터 물리 저장소
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use('/uploads', express.static(UPLOAD_DIR));

// 💾 OYP 통합 데이터베이스 (데이터+금융+보안)
const db = new sqlite3.Database(path.join(__dirname, 'oyp_integrated.db'));
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, hmj REAL, usd REAL, history TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS data_vault (fileId TEXT PRIMARY KEY, uploaderId TEXT, filename TEXT, filepath TEXT, Ad REAL, Bd REAL, size TEXT)`);
});

const upload = multer({ storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
})});

// 루트 접속 시 통합 UI 송출
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// [API] 로그인 및 자산 조회
app.get('/api/account/:id', (req, res) => {
    const accId = req.params.id;
    db.get('SELECT * FROM accounts WHERE id = ?', [accId], (err, row) => {
        if (!row) {
            const initHist = JSON.stringify([{ type: 'SYSTEM', msg: 'OYP 노드 가동 시작', time: new Date().toLocaleString() }]);
            db.run(`INSERT INTO accounts VALUES (?, 10.0, 100.0, ?)`, [accId, initHist], () => {
                res.json({ id: accId, hmj: 10, usd: 100, history: JSON.parse(initHist) });
            });
        } else { row.history = JSON.parse(row.history); res.json(row); }
    });
});

// [API] MARS-1 보안 업로드
app.post('/api/upload', upload.single('file'), (req, res) => {
    const { uploaderId, Ad, Bd } = req.body;
    const fileId = 'FID_' + Math.random().toString(36).substring(2, 8).toUpperCase();
    const size = (req.file.size / 1024 / 1024).toFixed(2) + 'MB';
    
    db.run(`INSERT INTO data_vault VALUES (?, ?, ?, ?, ?, ?, ?)`, 
        [fileId, uploaderId, req.file.originalname, `/uploads/${req.file.filename}`, Ad, Bd, size], 
        () => res.json({ success: true, fileId }));
});

// [API] 내 보안 파일 목록
app.get('/api/files/:id', (req, res) => {
    db.all(`SELECT * FROM data_vault WHERE uploaderId = ?`, [req.params.id], (err, rows) => res.json(rows));
});

// 실시간 통신 (Socket.io)
io.on('connection', (socket) => {
    socket.on('join', (id) => socket.join(id));
    socket.on('message', (data) => io.emit('receive', data));
});

server.listen(4000, '0.0.0.0', () => console.log('🚀 OYP 통합 노드 가동 중 (Port 4000)'));
