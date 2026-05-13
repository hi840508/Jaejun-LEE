const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto'); // 🔐 실제 타원 곡선 알고리즘 사용을 위한 모듈
const app = express();

app.use(cors());
app.use(express.json({ limit: '2000mb' }));
app.use(express.urlencoded({ limit: '2000mb', extended: true }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));

// 🧠 글로벌 통합 장부 및 터널
const DIMENSION_TUNNEL = new Map();
const LEDGER_BOOK = {};            
const USED_KEY_PAIRS = new Set(); // 영구 결번(블랙리스트) 관리

app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { usd: 1000, mb: 0, hmj: 0, history: [] };
    }
    res.json(LEDGER_BOOK[acc]);
});

/**
 * [API] 테스트용 타원 곡선(secp256k1) 키 쌍 생성기 (시연용)
 */
app.get('/generate-keypair', (req, res) => {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    res.json({
        privateKey: ecdh.getPrivateKey('hex'),
        publicKey: ecdh.getPublicKey('hex')
    });
});

/**
 * [API] HMJ 발행 (타원 곡선 대수학 수식 성립 검증)
 */
app.post('/mint-hmj', (req, res) => {
    const { accountId, publicKey, privateKey } = req.body;
    const keyPairStr = `${publicKey}:${privateKey}`;

    // 1. 글로벌 블랙리스트 검증 (사용된 키 쌍 영구 차단)
    if (USED_KEY_PAIRS.has(keyPairStr)) {
        return res.status(403).json({ error: "이미 사용된 키 쌍입니다. 영구적으로 재사용이 불가능합니다." });
    }

    try {
        // 2. 타원 곡선 대수학 검증 (P = d * G)
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(privateKey, 'hex');
        const derivedPublicKey = ecdh.getPublicKey('hex');

        // 입력한 공개키와 비밀키로 연산한 결과가 일치하는지 확인
        if (derivedPublicKey === publicKey) {
            USED_KEY_PAIRS.add(keyPairStr);
            LEDGER_BOOK[accountId].hmj += 1.000;
            LEDGER_BOOK[accountId].history.unshift({
                type: 'MINT', asset: 'HMJ', amount: '1.000', time: new Date().toLocaleString()
            });
            return res.json({ success: true, balance: LEDGER_BOOK[accountId].hmj });
        } else {
            return res.status(400).json({ error: "대수학 수식이 성립하지 않습니다. (키 쌍 불일치)" });
        }
    } catch (e) {
        return res.status(400).json({ error: "유효한 16진수(Hex) 형태의 타원 곡선 키가 아닙니다." });
    }
});

/**
 * [API] 자산 에스크로 송금 (터널 생성 및 잔고 선차감)
 */
app.post('/transfer-asset', (req, res) => {
    const { senderId, assetType, amount, secretKey } = req.body;
    const typeLower = assetType.toLowerCase();
    const val = parseFloat(amount);

    if (LEDGER_BOOK[senderId][typeLower] < val) {
        return res.status(400).json({ error: "잔고가 부족합니다." });
    }

    const tunnelId = Math.random().toString(36).substring(2, 10).toUpperCase();

    // 1. 송금자 잔고에서 선 차감
    LEDGER_BOOK[senderId][typeLower] -= val;
    LEDGER_BOOK[senderId].history.unshift({
        type: 'SEND (Escrow)', asset: assetType, amount: val, time: new Date().toLocaleString()
    });

    // 2. 터널에 자산과 수령 조건(secretKey) 보관
    DIMENSION_TUNNEL.set(tunnelId, { assetType, amount: val, secretKey });
    res.json({ tunnelId });
});

/**
 * [API] 자산 수신 (비밀키 입력 시 터널 해제 및 잔고 추가)
 */
app.post('/claim-asset', (req, res) => {
    const { receiverId, tunnelId, inputSecretKey } = req.body;
    const asset = DIMENSION_TUNNEL.get(tunnelId);

    if (!asset || asset.secretKey !== inputSecretKey) {
        return res.status(403).json({ error: "비밀키가 일치하지 않거나 만료된 터널입니다." });
    }

    // 수신자 잔고에 추가
    LEDGER_BOOK[receiverId][asset.assetType.toLowerCase()] += asset.amount;
    LEDGER_BOOK[receiverId].history.unshift({
        type: 'RCV (Claimed)', asset: asset.assetType, amount: asset.amount, time: new Date().toLocaleString()
    });

    DIMENSION_TUNNEL.delete(tunnelId);
    res.json({ success: true });
});

app.listen(4000, '0.0.0.0', () => console.log('🏦 RAY ALGEBRAIC BANK V5.5 ONLINE (ECC SECP256K1)'));
