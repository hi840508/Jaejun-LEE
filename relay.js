const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 서버 장부 및 자격 증명소
const DATA_TICKETS = new Map(); 
const LEDGER_BOOK = {};             
const ESCROW_TUNNEL = new Map();
const USED_POINTS = new Set();

app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { usd: 1, mb: 0, hmj: 1, asset_history: [
            { type: 'WELCOME', asset: 'USD', amount: '1.00', time: new Date().toLocaleString() },
            { type: 'WELCOME', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString() }
        ], file_history: [] };
    }
    res.json(LEDGER_BOOK[acc]);
});

// [HMJ 채굴]
app.post('/mint-hmj', (req, res) => {
    const { accountId, A, B, x, y } = req.body;
    const pointId = `${A}:${B}:${x}:${y}`;
    if (USED_POINTS.has(pointId)) return res.status(403).json({ error: "이미 사용된 좌표입니다." });
    
    if (Math.pow(parseInt(y), 2) === Math.pow(parseInt(x), 3) + (parseInt(A) * parseInt(x)) + parseInt(B)) {
        USED_POINTS.add(pointId);
        LEDGER_BOOK[accountId].hmj += 1.000;
        LEDGER_BOOK[accountId].asset_history.unshift({ type: 'MINT', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString() });
        res.json({ success: true, balance: LEDGER_BOOK[accountId].hmj });
    } else {
        res.status(400).json({ error: "수식이 성립하지 않습니다." });
    }
});

// [자산 송수신]
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount } = req.body;
    const typeLower = assetType.toLowerCase();
    if (!LEDGER_BOOK[senderId] || LEDGER_BOOK[senderId][typeLower] < parseFloat(amount)) return res.status(400).json({ error: "잔고가 부족합니다." });
    
    const ticketCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    LEDGER_BOOK[senderId][typeLower] -= parseFloat(amount);
    LEDGER_BOOK[senderId].asset_history.unshift({ type: 'SEND', asset: assetType, amount: parseFloat(amount), tunnel: ticketCode, time: new Date().toLocaleString() });
    ESCROW_TUNNEL.set(ticketCode, { assetType, amount: parseFloat(amount), senderId });
    res.json({ ticketCode });
});

app.post('/claim-asset', (req, res) => {
    const { receiverId, ticketCode } = req.body;
    const asset = ESCROW_TUNNEL.get(ticketCode);
    if (!asset) return res.status(403).json({ error: "유효하지 않은 티켓입니다." });
    
    LEDGER_BOOK[receiverId][asset.assetType.toLowerCase()] += asset.amount;
    LEDGER_BOOK[receiverId].asset_history.unshift({ type: 'RCV', asset: asset.assetType, amount: asset.amount, tunnel: ticketCode, time: new Date().toLocaleString() });
    ESCROW_TUNNEL.delete(ticketCode);
    res.json({ success: true, asset });
});

// [오프라인 데이터 티켓 발급 및 파기]
app.post('/auth-data-emit', (req, res) => {
    const { accountId, filename, sizeMB } = req.body;
    const ticketCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    
    DATA_TICKETS.set(ticketCode, { senderId: accountId, filename, sizeMB, isUsed: false });
    LEDGER_BOOK[accountId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'ENCRYPT', file: filename, size: sizeMB, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    res.json({ ticketCode });
});

app.post('/auth-data-claim', (req, res) => {
    const { receiverId, ticketCode } = req.body;
    const ticket = DATA_TICKETS.get(ticketCode);
    
    if (!ticket) return res.status(404).json({ error: "등록되지 않은 자격 증명입니다." });
    if (ticket.isUsed) return res.status(403).json({ error: "영구적으로 잠긴(파기된) 파일입니다." });

    ticket.isUsed = true; // 1회용 파기
    LEDGER_BOOK[receiverId].mb += parseFloat(ticket.sizeMB);
    LEDGER_BOOK[receiverId].file_history.unshift({ type: 'DECRYPT', file: ticket.filename, size: ticket.sizeMB, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    res.json({ success: true });
});

app.listen(4000, '0.0.0.0', () => console.log('🔴 MARS BANK V12.0 ONLINE'));
