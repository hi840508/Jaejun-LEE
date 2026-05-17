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

const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(__dirname));

// 📂 데이터 물리 저장소 (환자별 폴더 관리)
const BASE_DATA_DIR = path.join(__dirname, 'RAY_Data');
if (!fs.existsSync(BASE_DATA_DIR)) fs.mkdirSync(BASE_DATA_DIR, { recursive: true });
app.use('/data', express.static(BASE_DATA_DIR));

// 💾 통합 SQLite 데이터베이스
const db = new sqlite3.Database(path.join(__dirname, 'ray_integrated.db'));

db.serialize(() => {
    // 환자 정보 테이블
    db.run(`CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY, 
        name TEXT, 
        chartNumber TEXT, 
        gender TEXT, 
        birthDate TEXT, 
        history TEXT,
        diagData TEXT,
        syncPath TEXT
    )`);
});

// 📁 파일 업로드 설정 (카테고리별 저장)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const patientName = decodeURIComponent(req.headers['x-patient-name'] || 'Guest');
        const modality = decodeURIComponent(req.headers['x-target-modality'] || 'Files');
        const dir = path.join(BASE_DATA_DIR, patientName, modality);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage });

// --- [API] 환자 관리 ---
app.get('/api/patients', (req, res) => {
    db.all("SELECT * FROM patients", [], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/patients', (req, res) => {
    const p = req.body;
    db.run(`INSERT INTO patients (id, name, chartNumber, gender, birthDate) VALUES (?, ?, ?, ?, ?)`,
        [p.id, p.name, p.chartNumber, p.gender, p.birthDate], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
    });
});

app.put('/api/patients/:id', (req, res) => {
    const p = req.body;
    db.run(`UPDATE patients SET name=?, chartNumber=?, gender=?, birthDate=?, history=?, diagData=? WHERE id=?`,
        [p.name, p.chartNumber, p.gender, p.birthDate, p.history, p.diagData, req.params.id], (err) => {
            res.json({ success: true });
    });
});

// --- [API] 영상 및 파일 관리 ---
app.get('/api/patients/:name/images', (req, res) => {
    const patientName = req.params.name;
    const patientDir = path.join(BASE_DATA_DIR, patientName);
    let allFiles = [];

    if (fs.existsSync(patientDir)) {
        const modalities = fs.readdirSync(patientDir);
        modalities.forEach(mod => {
            const modDir = path.join(patientDir, mod);
            if (fs.statSync(modDir).isDirectory()) {
                const files = fs.readdirSync(modDir);
                files.forEach(file => {
                    const stats = fs.statSync(path.join(modDir, file));
                    allFiles.push({
                        name: file,
                        modality: mod,
                        src: `/data/${patientName}/${mod}/${file}`,
                        date: stats.mtime.toLocaleDateString(),
                        timestamp: stats.mtime.getTime()
                    });
                });
            }
        });
    }
    res.json(allFiles);
});

app.post('/api/upload', upload.single('file'), (req, res) => {
    io.emit('new_image_added', { patientId: req.headers['x-patient-id'] });
    res.json({ success: true });
});

app.post('/api/explore', (req, res) => {
    const targetPath = req.body.targetPath || BASE_DATA_DIR;
    if (!fs.existsSync(targetPath)) return res.json({ entries: [] });
    
    const entries = fs.readdirSync(targetPath).map(name => {
        const stats = fs.statSync(path.join(targetPath, name));
        return { name, isDirectory: stats.isDirectory() };
    });
    res.json({ entries });
});

// --- ⭐ [실시간 통신] 웹소켓 채팅 라우팅 ---
io.on('connection', (socket) => {
    console.log(`사용자 접속: ${socket.id}`);

    // 특정 방 입장
    socket.on('join_room', (roomId) => {
        socket.join(roomId);
        console.log(`${socket.id} 가 방 [${roomId}] 에 입장했습니다.`);
    });
    
    // 특정 방에서 나가기
    socket.on('leave_room', (roomId) => {
        socket.leave(roomId);
        console.log(`${socket.id} 가 방 [${roomId}] 에서 나갔습니다.`);
    });

    // P2P 메시지 릴레이 전송
    socket.on('send_message', (data) => {
        // 나를 제외한 방 안에 있는 모두에게 메시지 브로드캐스트
        socket.to(data.roomId).emit('receive_message', data);
    });

    socket.on('disconnect', () => {
        console.log(`사용자 연결 해제: ${socket.id}`);
    });
});

server.listen(PORT, '0.0.0.0', () => console.log(`🚀 OYP Commerce & Chat Server Running on Port ${PORT}`));
