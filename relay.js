const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(__dirname));

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use('/uploads', express.static(UPLOAD_DIR));

const db = new sqlite3.Database(path.join(__dirname, 'oyp_integrated.db'));
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, hmj REAL, usd REAL, history TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS patients (id TEXT PRIMARY KEY, name TEXT, chart TEXT, lastScan TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS data_vault (fileId TEXT PRIMARY KEY, uploaderId TEXT, filename TEXT, type TEXT, size TEXT)`);
});

// [AI Diagnostic Simulation] Panoramic Analyzer (OralGPT)
app.post('/api/ai/analyze', (req, res) => {
    const { fileId } = req.body;
    setTimeout(() => { // AI 분석 대기 시뮬레이션
        res.json({
            status: 'COMPLETED',
            findings: ['치주염 징후(24번)', '인접면 우식 의심(16번)', '상악동 거상술 권장'],
            confidence: 0.98
        });
    }, 2000);
});

app.get('/api/patients', (req, res) => {
    db.all(`SELECT * FROM patients`, [], (err, rows) => res.json(rows || []));
});

server.listen(4000, '0.0.0.0', () => console.log('🚀 OYP Enterprise Node 가동 중'));
