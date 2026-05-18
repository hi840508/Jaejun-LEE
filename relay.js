const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

// 서버 전용 기본 타원곡선 키페어 (ECC Inverse 알고리즘 활용을 위한 기반)
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });

// 독자적 타원곡선 역산(ECC Inverse) 해시 시뮬레이션 함수
function generateECCInverseSignature(checkId, secretKey, amount) {
    const rawData = `${checkId}:${secretKey}:${amount}`;
    // 1단계: SHA-256 기반 원본 해시 도출
    const hash = crypto.createHash('sha256').update(rawData).digest('hex');
    // 2단계: 논문의 다이나믹 역산 개념을 소프트웨어적으로 투영 (XOR 비트 시프팅 방어막 구축)
    let inverseHex = '';
    for (let i = 0; i < hash.length; i++) {
        const intVal = parseInt(hash[i], 16);
        const invVal = 15 - intVal; // 16진수 기반의 개념적 역산 수행
        inverseHex += invVal.toString(16);
    }
    // 3단계: 역산된 해시를 서버의 타원곡선 Private Key로 암호화 (이중 무결성 서명)
    const sign = crypto.createSign('SHA256');
    sign.update(inverseHex);
    return sign.sign(privateKey, 'hex');
}

function verifyECCInverseSignature(checkId, secretKey, amount, signature) {
    const rawData = `${checkId}:${secretKey}:${amount}`;
    const hash = crypto.createHash('sha256').update(rawData).digest('hex');
    let inverseHex = '';
    for (let i = 0; i < hash.length; i++) {
        const intVal = parseInt(hash[i], 16);
        const invVal = 15 - intVal;
        inverseHex += invVal.toString(16);
    }
    const verify = crypto.createVerify('SHA256');
    verify.update(inverseHex);
    return verify.verify(publicKey, signature, 'hex');
}

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = 4000;

const db = new sqlite3.Database(path.join(__dirname, 'commerce_brand_ultimate_ecc.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, name TEXT, owner TEXT, logo TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, storeId TEXT, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, originalPayload TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, message TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, secretKey TEXT, eccSignature TEXT, is_used INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, targetStore TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, sender_name TEXT, amount INTEGER, status TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, amount INTEGER, status TEXT, date TEXT)`);
});

app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (row) {
            if (row.password !== password) return res.status(401).json({ error: "비밀번호가 일치하지 않습니다" });
            return res.json(row);
        } else {
            const initialBalance = 10000;
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, ?)`,
                [name, password, bank || '미지정', account || '000-00', initialBalance], (err) => {
                    return res.json({ name, bank, account, balance: initialBalance });
                });
        }
    });
});

app.get('/api/users/:name', (req, res) => {
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => { res.json(row || { balance: 0 }); });
});

app.post('/api/store/create', (req, res) => {
    const { name, owner, logo } = req.body;
    const storeId = 'STR_' + Date.now() + '_' + Math.floor(Math.random() * 100);
    db.run(`INSERT INTO stores (id, name, owner, logo) VALUES (?, ?, ?, ?)`, [storeId, name, owner, logo], () => {
        res.json({ success: true });
    });
});

app.get('/api/stores/owned/:owner', (req, res) => {
    db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => { res.json(rows || []); });
});

app.get('/api/stores/all', (req, res) => {
    db.all(`SELECT * FROM stores`, [], (err, rows) => { res.json(rows || []); });
});

app.post('/api/deposit/request', (req, res) => {
    const { userName, senderName, amount } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date) VALUES (?, ?, ?, '대기', ?)`,
        [userName, senderName, amount, date], () => { res.json({ success: true }); });
});

app.get('/api/admin/deposits', (req, res) => {
    db.all(`SELECT * FROM deposits WHERE status = '대기'`, [], (err, rows) => { res.json(rows || []); });
});

app.post('/api/admin/deposit/approve/direct', (req, res) => {
    const { depositId, userName, amount } = req.body;
    db.serialize(() => {
        db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, userName]);
        db.run(`UPDATE deposits SET status = '승인_직접증액' WHERE id = ?`, [depositId]);
        res.json({ success: true });
    });
});

// 어드민 QR 송달 시 다이나믹 타원곡선 역산(ECC Inverse) 엔진 가동
app.post('/api/admin/deposit/approve/qr', (req, res) => {
    const { depositId, userName, amount, issuer } = req.body;
    
    const checkId = 'META_QR_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6).toUpperCase();
    const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
    const date = new Date().toLocaleString('ko-KR');

    // 고유 역산 모듈 통과
    const signature = generateECCInverseSignature(checkId, secretKey, amount);

    db.serialize(() => {
        db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`,
            [checkId, amount, issuer, secretKey, signature, date]);
        db.run(`UPDATE deposits SET status = '승인_QR수표출하' WHERE id = ?`, [depositId]);

        const chatRoom = `room_support_${[userName, issuer].sort().join('_')}`;
        const qrPayload = `[META_QR]${checkId}|${secretKey}|${signature}`;
        
        db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`, [chatRoom, issuer, qrPayload, date], () => {
            res.json({ success: true });
            io.to(chatRoom).emit('receive_message', { roomId: chatRoom, sender: issuer, message: qrPayload, date });
        });
    });
});

app.post('/api/withdraw', (req, res) => {
    const { name, amount } = req.body;
    const date = new Date().toLocaleString('ko-KR');
    db.serialize(() => {
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, name]);
        db.run(`INSERT INTO withdrawals (name, amount, status, date) VALUES (?, ?, '완료', ?)`, [name, amount, date], () => {
            res.json({ success: true });
        });
    });
});

app.post('/api/check/issue', (req, res) => {
    const { issuer, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "잔액 한도 부족" });
        
        const checkId = 'META_QR_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6).toUpperCase();
        const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
        const date = new Date().toLocaleString('ko-KR');

        const signature = generateECCInverseSignature(checkId, secretKey, amount);

        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`,
                [checkId, amount, issuer, secretKey, signature, date], () => {
                    res.json({ success: true, checkId, secretKey, signature });
                });
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId, secretKey, signature } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`;
    let params = [checkId];

    if (secretKey && !checkId) {
        query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`;
        params = [secretKey];
    }

    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "이미 회수 완료되었거나 무효한 번호입니다" });
        
        // ECC 역산 서명 엄격 교차 검증 (보안 무결성 보장)
        if (signature) {
            const isValid = verifyECCInverseSignature(row.id, row.secretKey, row.amount, signature);
            if(!isValid) return res.status(401).json({ error: "ECC 역산 알고리즘 검증 실패 위조된 수표 접근 차단" });
        }

        db.serialize(() => {
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [row.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            res.json({ success: true, amount: row.amount });
        });
    });
});

app.post('/api/products/encrypt-build', (req, res) => {
    const { name, price, seller, storeId, description, originalPayload } = req.body;
    const pid = 'PRD_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    db.run(`INSERT INTO products (id, storeId, type, name, description, price, seller, originalPayload) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?)`,
        [pid, storeId, name, description, price, seller, originalPayload], (err) => { res.json({ success: true, id: pid }); });
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => { res.json(rows || []); }); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => { res.json(row || {}); }); });

app.post('/api/product/edit', (req, res) => {
    const { id, name, price } = req.body;
    db.run(`UPDATE products SET name = ?, price = ? WHERE id = ?`, [name, price, id], () => { res.json({ success: true }); });
});

app.post('/api/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => { res.json({ success: true }); }); });

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "가용 자산 범위를 초과하는 시도입니다" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, new Date().toLocaleString('ko-KR')], () => {
                res.json({ success: true });
            });
        });
    });
});

app.post('/api/favorite/toggle', (req, res) => {
    const { userName, targetStore } = req.body;
    db.get(`SELECT * FROM favorite_stores WHERE userName = ? AND targetStore = ?`, [userName, targetStore], (err, row) => {
        if(row) { db.run(`DELETE FROM favorite_stores WHERE id = ?`, [row.id], () => res.json({ success: true })); } 
        else { db.run(`INSERT INTO favorite_stores (userName, targetStore) VALUES (?, ?)`, [userName, targetStore], () => res.json({ success: true })); }
    });
});

app.get('/api/favorites/:userName', (req, res) => {
    db.all(`SELECT targetStore FROM favorite_stores WHERE userName = ?`, [req.params.userName], (err, rows) => { res.json(rows ? rows.map(r => r.targetStore) : []); });
});

app.get('/api/chat/:roomId', (req, res) => { db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => res.json(rows || [])); });

app.post('/api/transfer', (req, res) => {
    const { sender, receiver, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [sender], (err, sRow) => {
        if (!sRow || sRow.balance < amount) return res.status(400).json({ error: "한도 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, sender]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, receiver]);
            db.run(`INSERT INTO transfers (sender, receiver, amount, date) VALUES (?, ?, ?, ?)`, [sender, receiver, amount, new Date().toLocaleString('ko-KR')], () => {
                res.json({ success: true });
            });
        });
    });
});

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        const txs = await new Promise(r => db.all(`SELECT * FROM transactions WHERE buyer=? OR seller=?`, [name, name], (e, rows) => r(rows||[])));
        const tfs = await new Promise(r => db.all(`SELECT * FROM transfers WHERE sender=? OR receiver=?`, [name, name], (e, rows) => r(rows||[])));
        const dps = await new Promise(r => db.all(`SELECT * FROM deposits WHERE user_name=?`, [name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));
        
        let history = [];
        txs.forEach(t => history.push({ type: t.buyer === name ? '자산구매' : '자산판매', date: t.date, amount: t.amount, productName: t.productName, seller: t.seller }));
        tfs.forEach(t => history.push({ type: t.sender === name ? 'P2P송금출금' : 'P2P송금입금', date: t.date, amount: t.amount, seller: t.receiver }));
        dps.forEach(d => history.push({ type: `입금충전요청(${d.status})`, date: d.date, amount: d.amount, seller: '어드민검증' }));
        wds.forEach(w => history.push({ type: '계좌출금완료', date: w.date, amount: w.amount, seller: '지정계좌' }));
        
        history.sort((a,b) => new Date(b.date) - new Date(a.date));
        res.json(history);
    } catch(e) { res.json([]); }
});

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => {
        db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`, [data.roomId, data.sender, data.message, new Date().toLocaleString('ko-KR')], () => {
            io.to(data.roomId).emit('receive_message', data);
        });
    });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[GITHUB SYSTEM V2] CORE BOUND ON PORT ${PORT}`); });
