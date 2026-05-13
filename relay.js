const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json()); // 대용량 설정 제거 (파일을 안 받으므로)

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 서버 장부 (파일 본문은 절대 저장하지 않음)
const ESCROW_TUNNEL = new Map();    
const DATA_TICKETS = new Map();     // 파일 열쇠 자격 증명소
const LEDGER_BOOK = {};             
const USED_POINTS = new Set();      

app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { usd: 1, mb: 0, hmj: 1, asset_history: [
            { type: 'MINT', asset: 'USD', amount: '1.00', time: new Date().toLocaleString() },
            { type: 'MINT', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString() }
        ], file_history: [] };
    }
    res.json(LEDGER_BOOK[acc]);
});

// [HMJ 채굴]
app.post('/mint-hmj', (req, res) => {
    const { accountId, A, B, x, y } = req.body;
    const pointId = `${A}:${B}:${x}:${y}`;
    if (USED_POINTS.has(pointId)) return res.status(403).json({ error: "이미 사용된 타원곡선 좌표입니다." });
    
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
    if (!asset) return res.status(403).json({ error: "유효하지 않거나 이미 사용된 티켓입니다." });
    
    LEDGER_BOOK[receiverId][asset.assetType.toLowerCase()] += asset.amount;
    LEDGER_BOOK[receiverId].asset_history.unshift({ type: 'RCV', asset: asset.assetType, amount: asset.amount, tunnel: ticketCode, time: new Date().toLocaleString() });
    ESCROW_TUNNEL.delete(ticketCode);
    res.json({ success: true, asset });
});

// 🚀 [신규: 오프라인 데이터 티켓 발급 및 파기]
app.post('/auth-data-emit', (req, res) => {
    const { accountId, filename, sizeMB } = req.body;
    const ticketCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    
    // 파일 내용은 없고, 자격 증명(상태)만 저장
    DATA_TICKETS.set(ticketCode, { senderId: accountId, filename, sizeMB, isUsed: false });
    
    LEDGER_BOOK[accountId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'SEND (Encrypted)', file: filename, size: sizeMB, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    res.json({ ticketCode });
});

app.post('/auth-data-claim', (req, res) => {
    const { receiverId, ticketCode } = req.body;
    const ticket = DATA_TICKETS.get(ticketCode);
    
    if (!ticket) return res.status(404).json({ error: "위조된 봉투이거나 서버에 등록되지 않은 자격 증명입니다." });
    if (ticket.isUsed) return res.status(403).json({ error: "이미 누군가 해독한 파일입니다. 영구적으로 잠겼습니다." });

    // 🔒 핵심 보안: 1회 열람 후 즉시 자격 증명 파기 (Burn)
    ticket.isUsed = true; 
    
    LEDGER_BOOK[receiverId].mb += parseFloat(ticket.sizeMB);
    LEDGER_BOOK[receiverId].file_history.unshift({ type: 'RCV (Decrypted)', file: ticket.filename, size: ticket.sizeMB, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    res.json({ success: true });
});

app.listen(4000, '0.0.0.0', () => console.log('🔴 MARS BANK V11.0 (Zero-Knowledge) ONLINE'));
