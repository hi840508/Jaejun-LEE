const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json({ limit: '2000mb' }));
app.use(express.urlencoded({ limit: '2000mb', extended: true }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 서버 통합 데이터 저장소
const DIMENSION_TUNNEL = new Map(); // 자산 터널
const LEDGER_BOOK = {};            // 개인별 장부 (USD, MB, HMJ)
const USED_KEY_PAIRS = new Set();  // 🔐 영구 등록 방지 블랙리스트

/**
 * [API] 계좌 동기화 (다중 자산 지원)
 */
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { 
            usd: 1000, 
            mb: 0, 
            hmj: 0, 
            history: [] 
        };
    }
    res.json(LEDGER_BOOK[acc]);
});

/**
 * [API] HMJ 자산 생성 (대수학적 식 성립 검증)
 */
app.post('/mint-hmj', (req, res) => {
    const { accountId, publicKey, privateKey } = req.body;
    const keyPairStr = `${publicKey}:${privateKey}`;

    // 1. 중복 사용 검증 (글로벌 블랙리스트)
    if (USED_KEY_PAIRS.has(keyPairStr)) {
        return res.status(403).json({ error: "이미 사용된 키 쌍입니다. 영구 등록이 불가능합니다." });
    }

    // 2. 대수학적 식 성립 검증 (예시: 두 키의 합이 짝수일 때 성립하는 가상의 로직)
    // PM님이 향후 실제 수식을 이 부분에 구현하시면 됩니다.
    const isValid = (publicKey.length + privateKey.length) % 2 === 0; 

    if (isValid) {
        USED_KEY_PAIRS.add(keyPairStr);
        LEDGER_BOOK[accountId].hmj += 1.000;
        LEDGER_BOOK[accountId].history.unshift({
            type: 'MINT',
            asset: 'HMJ',
            amount: '1.000',
            time: new Date().toLocaleString()
        });
        res.json({ success: true, balance: LEDGER_BOOK[accountId].hmj });
    } else {
        res.status(400).json({ error: "식이 성립하지 않습니다." });
    }
});

/**
 * [API] 자산 전송 (송신자 자격으로 터널 생성)
 */
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount, privateKey } = req.body;
    const tunnelId = Math.random().toString(36).substring(2, 12).toUpperCase();

    // 터널에 잠시 보관 (상대방이 비밀키를 맞출 때까지)
    DIMENSION_TUNNEL.set(tunnelId, { 
        senderId, assetType, amount, privateKey, status: 'PENDING' 
    });

    res.json({ tunnelId });
});

/**
 * [API] 자산 수신 (비밀키 입력 시 실제 차감 및 지급)
 */
app.post('/claim-asset', (req, res) => {
    const { receiverId, tunnelId, inputPrivateKey } = req.body;
    const asset = DIMENSION_TUNNEL.get(tunnelId);

    if (!asset || asset.privateKey !== inputPrivateKey) {
        return res.status(403).json({ error: "비밀키가 일치하지 않습니다." });
    }

    // 실제 전송 처리
    const amount = parseFloat(asset.amount);
    LEDGER_BOOK[asset.senderId][asset.assetType.toLowerCase()] -= amount;
    LEDGER_BOOK[receiverId][asset.assetType.toLowerCase()] += amount;

    // 내역 기록
    const log = { tunnel: tunnelId, amount: amount, time: new Date().toLocaleString() };
    LEDGER_BOOK[asset.senderId].history.unshift({ ...log, type: 'SEND', asset: asset.assetType });
    LEDGER_BOOK[receiverId].history.unshift({ ...log, type: 'RCV', asset: asset.assetType });

    DIMENSION_TUNNEL.delete(tunnelId);
    res.json({ success: true });
});

app.listen(4000, '0.0.0.0', () => console.log('🏦 RAY GLOBAL BANK ONLINE'));
