const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json({ limit: '100mb' }));

// 정적 파일 서빙 및 업로드 폴더 생성
app.use(express.static(__dirname));
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use('/uploads', express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage: storage });

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// 🧠 중앙 장부 (Ledger & Data Vault)
const LEDGER_BOOK = {};
const DATA_VAULT = new Map();
const TRADE_MARKET = new Map();
const ESCROW_TUNNEL = new Map();
const USED_POINTS = new Set();

// [1] 계정 초기화 및 조회
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { 
            usd: 100, mb: 0, hmj: 10, 
            owned_files: [], 
            history: [{ type: 'WELCOME', detail: '계정 생성 보너스', time: new Date().toLocaleString() }] 
        };
    }
    res.json(LEDGER_BOOK[acc]);
});

// [2] 자산 송수신 및 채굴 (기존 MARS 로직 유지)
app.post('/mint-hmj', (req, res) => {
    const { accountId, A, B, x, y } = req.body;
    const pointId = `${A}:${B}:${x}:${y}`;
    if (USED_POINTS.has(pointId)) return res.status(403).json({ error: "이미 사용된 좌표입니다." });
    
    if (Math.pow(parseInt(y), 2) === Math.pow(parseInt(x), 3) + (parseInt(A) * parseInt(x)) + parseInt(B)) {
        USED_POINTS.add(pointId);
        LEDGER_BOOK[accountId].hmj += 1.000;
        LEDGER_BOOK[accountId].history.unshift({ type: 'MINT', detail: '+1.000 HMJ (채굴)', time: new Date().toLocaleString() });
        res.json({ success: true, balance: LEDGER_BOOK[accountId].hmj });
    } else {
        res.status(400).json({ error: "수식이 성립하지 않습니다." });
    }
});

app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount } = req.body;
    const typeLower = assetType.toLowerCase();
    if (!LEDGER_BOOK[senderId] || LEDGER_BOOK[senderId][typeLower] < parseFloat(amount)) return res.status(400).json({ error: "잔고가 부족합니다." });
    
    const ticketCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    LEDGER_BOOK[senderId][typeLower] -= parseFloat(amount);
    LEDGER_BOOK[senderId].history.unshift({ type: 'SEND', detail: `-${amount} ${assetType} 송금 티켓 발행`, time: new Date().toLocaleString() });
    ESCROW_TUNNEL.set(ticketCode, { assetType, amount: parseFloat(amount), senderId });
    res.json({ ticketCode });
});

app.post('/claim-asset', (req, res) => {
    const { receiverId, ticketCode } = req.body;
    const asset = ESCROW_TUNNEL.get(ticketCode);
    if (!asset) return res.status(403).json({ error: "유효하지 않은 티켓입니다." });
    
    LEDGER_BOOK[receiverId][asset.assetType.toLowerCase()] += asset.amount;
    LEDGER_BOOK[receiverId].history.unshift({ type: 'RCV', detail: `+${asset.amount} ${asset.assetType} 수취 완료`, time: new Date().toLocaleString() });
    ESCROW_TUNNEL.delete(ticketCode);
    res.json({ success: true, asset });
});

// [3] 데이터 관리 (업로드)
app.post('/api/data/upload', upload.single('file'), (req, res) => {
    const { uploaderId, Ad, Bd } = req.body;
    const fileId = 'FILE_' + Math.random().toString(36).substring(2, 9).toUpperCase();
    const sizeMB = (req.file.size / (1024 * 1024)).toFixed(2);
    const filepath = `/uploads/${req.file.filename}`;

    DATA_VAULT.set(fileId, { fileId, uploaderId, filename: req.file.originalname, filepath, sizeMB, Ad, Bd });
    LEDGER_BOOK[uploaderId].owned_files.push(fileId);
    LEDGER_BOOK[uploaderId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[uploaderId].history.unshift({ type: 'UPLOAD', detail: `데이터 암호화 등록 (${sizeMB}MB)`, time: new Date().toLocaleString() });

    res.json({ success: true, fileId });
});

app.get('/api/data/myfiles/:accountId', (req, res) => {
    const acc = LEDGER_BOOK[req.params.accountId];
    if (!acc) return res.json([]);
    const myFiles = acc.owned_files.map(id => DATA_VAULT.get(id)).filter(Boolean);
    res.json(myFiles);
});

// [4] 데이터 거래 마켓
app.post('/api/trade/list', (req, res) => {
    const { sellerId, fileId, priceHMJ } = req.body;
    if (!DATA_VAULT.has(fileId)) return res.status(404).json({ error: "파일을 찾을 수 없습니다." });
    
    const tradeId = 'TRD_' + Date.now();
    TRADE_MARKET.set(tradeId, { tradeId, sellerId, fileId, priceHMJ, status: 'OPEN' });
    res.json({ success: true, tradeId });
});

app.get('/api/trade/market', (req, res) => {
    const openTrades = Array.from(TRADE_MARKET.values())
        .filter(t => t.status === 'OPEN')
        .map(t => {
            const fileData = DATA_VAULT.get(t.fileId);
            return { ...t, filename: fileData ? fileData.filename : 'Unknown' };
        });
    res.json(openTrades);
});

app.post('/api/trade/buy', (req, res) => {
    const { buyerId, tradeId } = req.body;
    const trade = TRADE_MARKET.get(tradeId);
    
    if (!trade || trade.status !== 'OPEN') return res.status(400).json({ error: "유효하지 않은 거래입니다." });
    if (trade.sellerId === buyerId) return res.status(400).json({ error: "본인의 데이터입니다." });

    const buyer = LEDGER_BOOK[buyerId];
    const seller = LEDGER_BOOK[trade.sellerId];
    
    if (buyer.hmj < trade.priceHMJ) return res.status(400).json({ error: "HMJ 잔고가 부족합니다." });

    // 결제 및 스마트 컨트랙트 권한 이전
    buyer.hmj -= trade.priceHMJ;
    seller.hmj += trade.priceHMJ;
    buyer.owned_files.push(trade.fileId);
    trade.status = 'CLOSED';

    buyer.history.unshift({ type: 'BUY', detail: `데이터 권한 구매 (-${trade.priceHMJ} HMJ)`, time: new Date().toLocaleString() });
    seller.history.unshift({ type: 'SELL', detail: `데이터 권한 판매 (+${trade.priceHMJ} HMJ)`, time: new Date().toLocaleString() });

    res.json({ success: true, fileId: trade.fileId });
});

// [5] Socket.io 실시간 채팅 및 알림
io.on('connection', (socket) => {
    socket.on('join_network', (accountId) => socket.join('GLOBAL_NETWORK'));
    socket.on('send_chat', (data) => io.to('GLOBAL_NETWORK').emit('receive_chat', data));
});

server.listen(4000, '0.0.0.0', () => console.log('🔴 MARS OYP Unified Node Running on Port 4000'));
