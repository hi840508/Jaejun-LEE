const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' })); // 자격 증명만 받으므로 한도 축소

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));
app.get('/status', (req, res) => res.json({ status: 'ONLINE' }));

// 🧠 서버 장부 및 자격 증명소
const DATA_TICKETS = new Map(); 
const LEDGER_BOOK = {};             
const ESCROW_TUNNEL = new Map();
const USED_POINTS = new Set();

// 계좌 동기화 (초기 보너스 지급)
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

// [오프라인 데이터 티켓 등록]
app.post('/auth-data-emit', (req, res) => {
    const { accountId, filename, sizeMB } = req.body;
    const ticketCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    
    // 파일 내용은 저장하지 않고 티켓 상태만 생성
    DATA_TICKETS.set(ticketCode, { senderId: accountId, filename, sizeMB, isUsed: false });
    
    LEDGER_BOOK[accountId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'SEND (OFFLINE)', file: filename, size: sizeMB, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    res.json({ ticketCode });
});

// [오프라인 데이터 티켓 검증 및 파기]
app.post('/auth-data-claim', (req, res) => {
    const { receiverId, ticketCode } = req.body;
    const ticket = DATA_TICKETS.get(ticketCode);
    
    if (!ticket) return res.status(404).json({ error: "등록되지 않은 자격 증명입니다." });
    if (ticket.isUsed) return res.status(403).json({ error: "이미 파기된 티켓입니다. 해독이 불가능합니다." });

    // 🔒 1회용 보안: 검증 즉시 파기
    ticket.isUsed = true; 
    
    if (!LEDGER_BOOK[receiverId]) LEDGER_BOOK[receiverId] = { usd: 1, mb: 0, hmj: 1, asset_history: [], file_history: [] };
    LEDGER_BOOK[receiverId].mb += parseFloat(ticket.sizeMB);
    LEDGER_BOOK[receiverId].file_history.unshift({ type: 'RCV (DECRYPT)', file: ticket.filename, size: ticket.sizeMB, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    res.json({ success: true });
});

// [자산 송수신 / HMJ 채굴 생략 - 이전 V10 버전 유지]
app.post('/mint-hmj', (req, res) => { /* 동일 */ });
app.post('/transfer-asset', (req, res) => { /* 동일 */ });
app.post('/claim-asset', (req, res) => { /* 동일 */ });

app.listen(4000, '0.0.0.0', () => console.log('🔴 MARS BANK V11.5 ONLINE'));
