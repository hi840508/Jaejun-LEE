const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json({ limit: '2000mb' })); 
app.use(express.urlencoded({ limit: '2000mb', extended: true }));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'terminal.html')));
app.get('/status', (req, res) => res.json({ status: 'ONLINE' }));

const DIMENSION_TUNNEL = new Map();
const LEDGER_BOOK = {};

app.get('/account/:accountId', (req, res) => {
    const acc = req.params.accountId;
    if (!LEDGER_BOOK[acc]) {
        LEDGER_BOOK[acc] = { totalEmitted: 0, totalReceived: 0, history: [] };
    }
    let activeTunnels = 0;
    DIMENSION_TUNNEL.forEach((val) => { if (val.owner === acc) activeTunnels++; });
    
    res.json({ ...LEDGER_BOOK[acc], activeTunnels });
});

app.post('/emit', (req, res) => {
    try {
        const { accountId, matrix, scale, metadata } = req.body;
        const tunnelId = Math.random().toString(36).substring(2, 12).toUpperCase();
        const sizeMB = (metadata.s / (1024 * 1024)).toFixed(2);
        
        DIMENSION_TUNNEL.set(tunnelId, { owner: accountId, matrix, scale, metadata, createdAt: Date.now() });
        
        if (!LEDGER_BOOK[accountId]) LEDGER_BOOK[accountId] = { totalEmitted: 0, totalReceived: 0, history: [] };
        LEDGER_BOOK[accountId].totalEmitted += parseFloat(sizeMB);
        LEDGER_BOOK[accountId].history.unshift({ 
            type: 'EMIT (투영)', tunnel: tunnelId, file: metadata.n, size: `${sizeMB} MB`, time: new Date().toLocaleString('ko-KR')
        });

        setTimeout(() => {
            if(DIMENSION_TUNNEL.has(tunnelId)) DIMENSION_TUNNEL.delete(tunnelId);
        }, 10 * 60 * 1000);
        
        res.json({ tunnelId });
    } catch (e) { res.status(500).json({ error: "투영 실패" }); }
});

app.post('/summon/:tunnelId', (req, res) => {
    const { tunnelId } = req.params;
    const { accountId } = req.body; 

    if (!DIMENSION_TUNNEL.has(tunnelId)) return res.status(404).json({ error: "터널 만료" });

    const asset = DIMENSION_TUNNEL.get(tunnelId);
    const sizeMB = (asset.metadata.s / (1024 * 1024)).toFixed(2);

    if (!LEDGER_BOOK[accountId]) LEDGER_BOOK[accountId] = { totalEmitted: 0, totalReceived: 0, history: [] };
    LEDGER_BOOK[accountId].totalReceived += parseFloat(sizeMB);
    LEDGER_BOOK[accountId].history.unshift({ 
        type: 'RCV (실체화)', tunnel: tunnelId, file: asset.metadata.n, size: `${sizeMB} MB`, time: new Date().toLocaleString('ko-KR')
    });

    DIMENSION_TUNNEL.delete(tunnelId); 
    
    res.json(asset);
});

const PORT = 4000;
app.listen(PORT, '0.0.0.0', () => { console.log(`🏦 RAY BANK V3 ONLINE (PORT: 4000)`); });