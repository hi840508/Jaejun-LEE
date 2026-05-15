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
app.use(express.static(__dirname));

// AWS 환경에 맞춘 상대 경로 데이터 저장소 (서버 내부에 저장)
const DATA_DIR = path.join(__dirname, 'RAY_Cloud_Data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
app.use('/data', express.static(DATA_DIR));

// 💾 SQLite DB 설정 (금융 장부 + 데이터 마켓 통합)
const dbPath = path.join(__dirname, 'oqp_platform.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    // 유저 지갑 및 자산 장부
    db.run(`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, usd REAL, hmj REAL, mb REAL, history TEXT)`);
    // 암호화된 파일 금고
    db.run(`CREATE TABLE IF NOT EXISTS data_vault (fileId TEXT PRIMARY KEY, uploaderId TEXT, filename TEXT, sizeMB REAL, filepath TEXT, ad_key REAL, bd_key REAL, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    // 데이터 거래 마켓
    db.run(`CREATE TABLE IF NOT EXISTS trade_market (tradeId TEXT PRIMARY KEY, sellerId TEXT, fileId TEXT, priceHMJ REAL, status TEXT, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    // 소유권(접근 권한) 맵핑
    db.run(`CREATE TABLE IF NOT EXISTS file_ownership (fileId TEXT, ownerId TEXT, PRIMARY KEY (fileId, ownerId))`);
});

// 파일 업로드 설정 (Multer)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, DATA_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/[\\/:*?"<>|]/g, '_'))
});
const upload = multer({ storage: storage });

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// --- [1] 통합 로그인 및 지갑 초기화 ---
app.post('/api/login', (req, res) => {
    const { accountId } = req.body;
    db.get('SELECT * FROM accounts WHERE id = ?', [accountId], (err, row) => {
        if (!row) {
            const initHistory = JSON.stringify([{ type: 'WELCOME', detail: '계정 생성 보너스', time: new Date().toLocaleString() }]);
            db.run(`INSERT INTO accounts (id, usd, hmj, mb, history) VALUES (?, 100, 10, 0, ?)`, [accountId, initHistory], () => {
                res.json({ success: true, account: { id: accountId, usd: 100, hmj: 10, mb: 0, history: JSON.parse(initHistory) } });
            });
        } else {
            row.history = JSON.parse(row.history);
            res.json({ success: true, account: row });
        }
    });
});

// --- [2] 암호화 데이터 등록 (데이터 관리) ---
app.post('/api/data/upload', upload.single('file'), (req, res) => {
    const { uploaderId, Ad, Bd } = req.body;
    const fileId = 'FILE_' + Math.random().toString(36).substring(2, 10).toUpperCase();
    const sizeMB = (req.file.size / (1024 * 1024)).toFixed(2);
    const filepath = `/data/${req.file.filename}`;

    db.serialize(() => {
        db.run(`INSERT INTO data_vault (fileId, uploaderId, filename, sizeMB, filepath, ad_key, bd_key) VALUES (?, ?, ?, ?, ?, ?, ?)`, 
            [fileId, uploaderId, req.file.originalname, sizeMB, filepath, Ad, Bd]);
        db.run(`INSERT INTO file_ownership (fileId, ownerId) VALUES (?, ?)`, [fileId, uploaderId]);
        db.run(`UPDATE accounts SET mb = mb + ? WHERE id = ?`, [sizeMB, uploaderId], () => {
            res.json({ success: true, fileId, filepath });
        });
    });
});

// --- [3] 내 소유 데이터 조회 (데이터 보기) ---
app.get('/api/data/myfiles/:accountId', (req, res) => {
    const query = `
        SELECT v.fileId, v.filename, v.filepath, v.sizeMB, v.ad_key, v.bd_key 
        FROM data_vault v JOIN file_ownership o ON v.fileId = o.fileId 
        WHERE o.ownerId = ? ORDER BY v.createdAt DESC
    `;
    db.all(query, [req.params.accountId], (err, rows) => res.json(rows || []));
});

// --- [4] 데이터 마켓 등록 ---
app.post('/api/trade/list', (req, res) => {
    const { sellerId, fileId, priceHMJ } = req.body;
    const tradeId = 'TRD_' + Date.now();
    db.run(`INSERT INTO trade_market (tradeId, sellerId, fileId, priceHMJ, status) VALUES (?, ?, ?, ?, 'OPEN')`, 
        [tradeId, sellerId, fileId, priceHMJ], () => res.json({ success: true, tradeId })
    );
});

// --- [5] 마켓 조회 및 구매 (스마트 컨트랙트) ---
app.get('/api/trade/market', (req, res) => {
    const query = `SELECT t.*, v.filename FROM trade_market t JOIN data_vault v ON t.fileId = v.fileId WHERE t.status = 'OPEN' ORDER BY t.createdAt DESC`;
    db.all(query, [], (err, rows) => res.json(rows || []));
});

app.post('/api/trade/buy', (req, res) => {
    const { buyerId, tradeId } = req.body;
    db.get(`SELECT * FROM trade_market WHERE tradeId = ? AND status = 'OPEN'`, [tradeId], (err, trade) => {
        if (!trade) return res.status(400).json({ error: "유효하지 않은 거래입니다." });
        if (trade.sellerId === buyerId) return res.status(400).json({ error: "본인의 데이터입니다." });

        db.get(`SELECT hmj FROM accounts WHERE id = ?`, [buyerId], (err, buyer) => {
            if (buyer.hmj < trade.priceHMJ) return res.status(400).json({ error: "HMJ 잔고가 부족합니다." });

            db.serialize(() => {
                // 자산 이동
                db.run(`UPDATE accounts SET hmj = hmj - ? WHERE id = ?`, [trade.priceHMJ, buyerId]);
                db.run(`UPDATE accounts SET hmj = hmj + ? WHERE id = ?`, [trade.priceHMJ, trade.sellerId]);
                // 소유권(열람 권한) 부여
                db.run(`INSERT OR IGNORE INTO file_ownership (fileId, ownerId) VALUES (?, ?)`, [trade.fileId, buyerId]);
                // 마켓 상태 변경
                db.run(`UPDATE trade_market SET status = 'CLOSED' WHERE tradeId = ?`, [tradeId]);
                res.json({ success: true, fileId: trade.fileId });
            });
        });
    });
});

// --- [6] Socket.io 화상채팅 및 실시간 통신 ---
io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => socket.join(roomId));
    socket.on('send_message', (data) => io.to(data.roomId).emit('receive_message', data));
});

server.listen(PORT, '0.0.0.0', () => console.log(`🚀 MARS-1 AWS Server Running on Port ${PORT}`));
