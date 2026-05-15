const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(__dirname));

// 업로드 폴더 생성
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use('/uploads', express.static(UPLOAD_DIR));

// ⭐ 핵심 수정: 루트(/) 접속 시 무조건 index.html을 보내도록 고정
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- [이하 기존 장부 및 데이터 거래 로직 (보내드린 통합본 사용)] ---
// ... (생략된 로직은 이전 답변의 relay.js 통합 코드를 사용하세요) ...

server.listen(4000, '0.0.0.0', () => console.log('🔴 MARS OYP NODE ONLINE (Port 4000)'));
