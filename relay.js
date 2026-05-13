const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json({ limit: '2000mb' }));
app.use(express.urlencoded({ limit: '2000mb', extended: true }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 서버 통합 데이터 저장소
const DIMENSION_TUNNEL = new Map(); // 파일 전송 터널
const ESCROW_TUNNEL = new Map();    // 자산 전송 터널
const LEDGER_BOOK = {};             // 개인별 장부
const USED_POINTS = new Set();      // 🔐 타원곡선 사용된 좌표 블랙리스트

app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { 
            usd: 1000, mb: 0, hmj: 0, 
            asset_history: [], file_history: [] 
        };
    }
    res.json(LEDGER_BOOK[acc]);
});

/**
 * [API] HMJ 자산 생성 (타원 곡선 정수 연산 검증)
 * 방정식: y^2 = x^3 + Ax + B
 */
app.post('/mint-hmj', (req, res) => {
    const { accountId, A, B, x, y } = req.body;
    
    // 문자열을 정수로 변환
    const a = parseInt(A); const b = parseInt(B);
    const px = parseInt(x); const py = parseInt(y);

    const pointId = `${a}:${b}:${px}:${py}`;

    // 1. 중복 좌표 사용 검증 (블랙리스트)
    if (USED_POINTS.has(pointId)) {
        return res.status(403).json({ error: "이미 사용된 타원곡선 좌표(키 쌍)입니다. 영구 등록이 불가능합니다." });
    }

    // 2. 대수학적 식 성립 검증: y^2 == x^3 + Ax + B
    const leftSide = Math.pow(py, 2);
    const rightSide = Math.pow(px, 3) + (a * px) + b;

    if (leftSide === rightSide) {
        USED_POINTS.add(pointId);
        LEDGER_BOOK[accountId].hmj += 1.000;
        LEDGER_BOOK[accountId].asset_history.unshift({
            type: 'MINT', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString()
        });
        res.json({ success: true, balance: LEDGER_BOOK[accountId].hmj });
    } else {
        res.status(400).json({ error: `수식이 성립하지 않습니다. (좌항: ${leftSide} ≠ 우항: ${rightSide})` });
    }
});

// --- 파일 전송 로직 ---
app.post('/emit', (req, res) => {
    const { accountId, metadata } = req.body;
    const tunnelId = Math.random().toString(36).substring(2, 10).toUpperCase();
    const sizeMB = (metadata.s / (1024 * 1024)).toFixed(2);
    
    DIMENSION_TUNNEL.set(tunnelId, { owner: accountId, metadata, sizeMB });
    LEDGER_BOOK[accountId].mb += parseFloat(sizeMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'SEND', file: metadata.n, size: sizeMB, tunnel: tunnelId, time: new Date().toLocaleString() });
    res.json({ tunnelId });
});

app.post('/summon/:tunnelId', (req, res) => {
    const { tunnelId } = req.params;
    const { accountId } = req.body;
    const asset = DIMENSION_TUNNEL.get(tunnelId);
    if (!asset) return res.status(404).json({ error: "터널이 만료되었습니다." });

    LEDGER_BOOK[accountId].mb += parseFloat(asset.sizeMB);
    LEDGER_BOOK[accountId].file_history.unshift({ type: 'RCV', file: asset.metadata.n, size: asset.sizeMB, tunnel: tunnelId, time: new Date().toLocaleString() });
    DIMENSION_TUNNEL.delete(tunnelId);
    res.json(asset);
});

// --- 자산 전송 로직 ---
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount, secretKey } = req.body;
    const typeLower = assetType.toLowerCase();
    const val = parseFloat(amount);

    if (LEDGER_BOOK[senderId][typeLower] < val) return res.status(400).json({ error: "잔고가 부족합니다." });

    const tunnelId = Math.random().toString(36).substring(2, 10).toUpperCase();
    LEDGER_BOOK[senderId][typeLower] -= val;
    LEDGER_BOOK[senderId].asset_history.unshift({ type: 'SEND', asset: assetType, amount: val, time: new Date().toLocaleString() });
    
    ESCROW_TUNNEL.set(tunnelId, { assetType, amount: val, secretKey, senderId });
    res.json({ tunnelId });
});

app.post('/claim-asset', (req, res) => {
    const { receiverId, tunnelId, inputSecretKey } = req.body;
    const asset = ESCROW_TUNNEL.get(tunnelId);

    if (!asset || asset.secretKey !== inputSecretKey) return res.status(403).json({ error: "비밀키가 일치하지 않습니다." });

    LEDGER_BOOK[receiverId][asset.assetType.toLowerCase()] += asset.amount;
    LEDGER_BOOK[receiverId].asset_history.unshift({ type: 'RCV', asset: asset.assetType, amount: asset.amount, time: new Date().toLocaleString() });
    
    ESCROW_TUNNEL.delete(tunnelId);
    res.json({ success: true });
});

app.listen(4000, '0.0.0.0', () => console.log('🔴 MARS BANK ONLINE'));
