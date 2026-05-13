const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
// WebRTC 신호 교환을 위한 소켓 서버
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 서버 장부 데이터 (파일은 저장하지 않음)
const ESCROW_TUNNEL = new Map();    
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

// [HMJ 채굴 로직]
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

// [자산 송수신 로직]
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount } = req.body;
    if (!LEDGER_BOOK[senderId] || LEDGER_BOOK[senderId][assetType.toLowerCase()] < parseFloat(amount)) return res.status(400).json({ error: "잔고가 부족합니다." });
    const ticketCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    LEDGER_BOOK[senderId][assetType.toLowerCase()] -= parseFloat(amount);
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

// [파일 데이터 장부 기록용 API] - 실제 파일은 P2P로 전송됨
app.post('/log-file-transfer', (req, res) => {
    const { senderId, receiverId, fileName, sizeMB, tunnelId } = req.body;
    LEDGER_BOOK[senderId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[receiverId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[senderId].file_history.unshift({ type: 'SEND (P2P)', file: fileName, size: sizeMB, tunnel: tunnelId, time: new Date().toLocaleString() });
    LEDGER_BOOK[receiverId].file_history.unshift({ type: 'RCV (P2P)', file: fileName, size: sizeMB, tunnel: tunnelId, time: new Date().toLocaleString() });
    res.json({ success: true });
});

// 🚀 WebRTC Signaling (P2P 연결 중계기)
io.on('connection', (socket) => {
    socket.on('join-room', (roomId) => {
        socket.join(roomId);
        // 수신자가 들어오면 송신자에게 알려 P2P 연결 시작
        socket.to(roomId).emit('peer-joined'); 
    });
    socket.on('webrtc-offer', (data) => socket.to(data.roomId).emit('webrtc-offer', data.offer));
    socket.on('webrtc-answer', (data) => socket.to(data.roomId).emit('webrtc-answer', data.answer));
    socket.on('webrtc-ice', (data) => socket.to(data.roomId).emit('webrtc-ice', data.candidate));
});

server.listen(4000, '0.0.0.0', () => console.log('🔴 MARS BANK V10.0 (WebRTC P2P) ONLINE'));
