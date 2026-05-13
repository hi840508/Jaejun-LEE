const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json({ limit: '2000mb' }));
app.use(express.urlencoded({ limit: '2000mb', extended: true }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 서버 통합 데이터 저장소
const DIMENSION_TUNNEL = new Map(); 
const ESCROW_TUNNEL = new Map();    
const LEDGER_BOOK = {};             
const USED_POINTS = new Set();      

// [초기 가입 보너스 로직 추가]
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        // 최초 접속 시 1 USD, 1 HMJ 지급
        LEDGER_BOOK[acc] = { 
            usd: 1, 
            mb: 0, 
            hmj: 1, 
            asset_history: [
                { type: 'MINT', asset: 'USD', amount: '1.00', time: new Date().toLocaleString() },
                { type: 'MINT', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString() }
            ], 
            file_history: [] 
        };
    }
    res.json(LEDGER_BOOK[acc]);
});

// [HMJ 채굴]
app.post('/mint-hmj', (req, res) => {
    const { accountId, A, B, x, y } = req.body;
    const a = parseInt(A); const b = parseInt(B);
    const px = parseInt(x); const py = parseInt(y);
    const pointId = `${a}:${b}:${px}:${py}`;

    if (USED_POINTS.has(pointId)) return res.status(403).json({ error: "이미 사용된 타원곡선 좌표입니다." });

    if (Math.pow(py, 2) === Math.pow(px, 3) + (a * px) + b) {
        USED_POINTS.add(pointId);
        LEDGER_BOOK[accountId].hmj += 1.000;
        LEDGER_BOOK[accountId].asset_history.unshift({ type: 'MINT', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString() });
        res.json({ success: true, balance: LEDGER_BOOK[accountId].hmj });
    } else {
        res.status(400).json({ error: "수식이 성립하지 않습니다." });
    }
});

// [파일 전송] (수정 없음)
app.post('/emit', (req, res) => {
    const { accountId, fileData } = req.body;
    const tunnelId = Math.random().toString(36).substring(2, 8).toUpperCase(); // 6자리 숏코드
    const compressedMB = ((fileData.size / (1024 * 1024)) * 0.45).toFixed(2); 
    
    DIMENSION_TUNNEL.set(tunnelId, { owner: accountId, fileData, compressedMB });
    LEDGER_BOOK[accountId].mb += parseFloat(compressedMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'SEND', file: fileData.name, size: compressedMB, tunnel: tunnelId, time: new Date().toLocaleString() });
    res.json({ tunnelId, compressedMB });
});

app.post('/summon/:tunnelId', (req, res) => {
    const { tunnelId } = req.params;
    const { accountId } = req.body;
    const asset = DIMENSION_TUNNEL.get(tunnelId);
    
    if (!asset) return res.status(404).json({ error: "만료된 파일 티켓입니다." });

    LEDGER_BOOK[accountId].mb += parseFloat(asset.compressedMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'RCV', file: asset.fileData.name, size: asset.compressedMB, tunnel: tunnelId, time: new Date().toLocaleString() });
    DIMENSION_TUNNEL.delete(tunnelId); 
    res.json(asset);
});

// [자산 전송 / 수령] 비밀번호 로직 제거
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount } = req.body;
    const typeLower = assetType.toLowerCase();
    const val = parseFloat(amount);

    if (!LEDGER_BOOK[senderId] || LEDGER_BOOK[senderId][typeLower] < val) return res.status(400).json({ error: "잔고가 부족합니다." });

    // 6자리 난수 티켓 발급
    const ticketCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    
    LEDGER_BOOK[senderId][typeLower] -= val;
    LEDGER_BOOK[senderId].asset_history.unshift({ type: 'SEND', asset: assetType, amount: val, tunnel: ticketCode, time: new Date().toLocaleString() });
    
    ESCROW_TUNNEL.set(ticketCode, { assetType, amount: val, senderId });
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

app.listen(4000, '0.0.0.0', () => console.log('🔴 MARS BANK V9.0 ONLINE'));
