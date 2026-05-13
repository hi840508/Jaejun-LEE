const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

// 데이터 뱅크 특성상 대용량(3D 모델 등) 처리를 위해 제한 해제
app.use(cors());
app.use(express.json({ limit: '2000mb' })); 
app.use(express.urlencoded({ limit: '2000mb', extended: true }));

// 기본 경로 접속 시 단말기 화면 제공
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));
app.get('/status', (req, res) => res.json({ status: 'ONLINE' }));

// 🧠 휘발성 차원 터널 (원본 데이터 보관)
const DIMENSION_TUNNEL = new Map();
// 📒 중앙 영구 장부 (메타데이터 및 잔고 기록)
const LEDGER_BOOK = {};

/**
 * [API] 내 계좌 정보 및 이체 내역 조회
 * - 자격 증명(ID)이 없으면 새로 생성
 */
app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    
    if (!acc || !acc.startsWith('RAY-')) {
        return res.status(403).json({ error: "Invalid Credential" });
    }

    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { totalEmitted: 0, totalReceived: 0, history: [] };
    }
    
    // 현재 내가 생성했지만 아직 상대방이 수신하지 않은 활성 터널 수 계산
    let activeTunnels = 0;
    DIMENSION_TUNNEL.forEach((val) => { if (val.owner === acc) activeTunnels++; });
    
    res.json({ ...LEDGER_BOOK[acc], activeTunnels });
});

/**
 * [Emitter] 데이터 투영 (송금)
 */
app.post('/emit', (req, res) => {
    try {
        const { accountId, matrix, scale, metadata } = req.body;
        const tunnelId = Math.random().toString(36).substring(2, 12).toUpperCase();
        const sizeMB = (metadata.s / (1024 * 1024)).toFixed(2);
        
        // 터널에 데이터 저장 (소유자 정보 포함)
        DIMENSION_TUNNEL.set(tunnelId, { 
            owner: accountId, 
            matrix, 
            scale, 
            metadata, 
            createdAt: Date.now() 
        });
        
        // 장부에 기록
        if (!LEDGER_BOOK[accountId]) LEDGER_BOOK[accountId] = { totalEmitted: 0, totalReceived: 0, history: [] };
        LEDGER_BOOK[accountId].totalEmitted += parseFloat(sizeMB);
        LEDGER_BOOK[accountId].history.unshift({ 
            type: 'EMIT (송금)', 
            tunnel: tunnelId, 
            file: metadata.n, 
            size: `${sizeMB} MB`, 
            time: new Date().toLocaleString('ko-KR')
        });

        // 10분 후 자동 소멸 (보안)
        setTimeout(() => {
            if(DIMENSION_TUNNEL.has(tunnelId)) DIMENSION_TUNNEL.delete(tunnelId);
        }, 10 * 60 * 1000);
        
        res.json({ tunnelId });
    } catch (e) {
        res.status(500).json({ error: "투영 실패" });
    }
});

/**
 * [Materializer] 데이터 실체화 (수신 및 증발)
 */
app.post('/summon/:tunnelId', (req, res) => {
    const { tunnelId } = req.params;
    const { accountId } = req.body; // 수신자 자격 증명

    if (!DIMENSION_TUNNEL.has(tunnelId)) {
        return res.status(404).json({ error: "터널이 만료되었거나 존재하지 않습니다." });
    }

    const asset = DIMENSION_TUNNEL.get(tunnelId);
    const sizeMB = (asset.metadata.s / (1024 * 1024)).toFixed(2);

    // 수신자 장부에 기록
    if (!LEDGER_BOOK[accountId]) LEDGER_BOOK[accountId] = { totalEmitted: 0, totalReceived: 0, history: [] };
    LEDGER_BOOK[accountId].totalReceived += parseFloat(sizeMB);
    LEDGER_BOOK[accountId].history.unshift({ 
        type: 'RCV (수신)', 
        tunnel: tunnelId, 
        file: asset.metadata.n, 
        size: `${sizeMB} MB`, 
        time: new Date().toLocaleString('ko-KR')
    });

    // 데이터 영구 증발 (RAM에서 삭제)
    DIMENSION_TUNNEL.delete(tunnelId); 
    
    res.json(asset);
});

const PORT = 4000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🏦 RAY ALGEBRAIC BANK V3.5 ONLINE (PORT: 4000)`);
});
