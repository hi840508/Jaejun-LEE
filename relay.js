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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });

// 다이나믹 역산 서명 생성기 (논문 로직 시뮬레이션)
function generateECCInverseSignature(checkId, secretKey, amount) {
    const rawData = `${checkId}:${secretKey}:${amount}`;
    const hash = crypto.createHash('sha256').update(rawData).digest('hex');
    let inverseHex = '';
    for (let i = 0; i < hash.length; i++) {
        inverseHex += (15 - parseInt(hash[i], 16)).toString(16);
    }
    const sign = crypto.createSign('SHA256'); sign.update(inverseHex);
    return sign.sign(privateKey, 'hex');
}

function verifyECCInverseSignature(checkId, secretKey, amount, signature) {
    const hash = crypto.createHash('sha256').update(`${checkId}:${secretKey}:${amount}`).digest('hex');
    let inverseHex = '';
    for (let i = 0; i < hash.length; i++) { inverseHex += (15 - parseInt(hash[i], 16)).toString(16); }
    const verify = crypto.createVerify('SHA256'); verify.update(inverseHex);
    return verify.verify(publicKey, signature, 'hex');
}

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = 4000;

const db = new sqlite3.Database(path.join(__dirname, 'commerce_master_ultimate.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, name TEXT, owner TEXT, logo TEXT, status TEXT DEFAULT 'active')`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, storeId TEXT, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, thumbnail TEXT, encryptedPayload TEXT)`);
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
            if (row.password !== password) return res.status(401).json({ error: "비밀번호 오류" });
            return res.json(row);
        } else {
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, 10000)`, [name, password, bank, account], () => {
                res.json({ name, bank, account, balance: 10000 });
            });
        }
    });
});
app.get('/api/users/:name', (req, res) => { db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => { res.json(row || { balance: 0 }); }); });

// 상점 (Brand) 개설 및 상태 관리 API
app.post('/api/store/create', (req, res) => {
    const { name, owner, logo } = req.body;
    const storeId = 'STR_' + Date.now() + '_' + Math.floor(Math.random() * 100);
    db.run(`INSERT INTO stores (id, name, owner, logo, status) VALUES (?, ?, ?, ?, 'active')`, [storeId, name, owner, logo], () => { res.json({ success: true }); });
});
app.get('/api/stores/owned/:owner', (req, res) => { db.all(`SELECT * FROM stores WHERE owner = ?`, [req.params.owner], (err, rows) => { res.json(rows || []); }); });
app.post('/api/store/status', (req, res) => { db.run(`UPDATE stores SET status = ? WHERE id = ?`, [req.body.status, req.body.id], () => { res.json({ success: true }); }); });

// 마켓 검색용 상점 (수정 중인 상점은 노출 안됨)
app.get('/api/stores/active', (req, res) => { db.all(`SELECT * FROM stores WHERE status = 'active'`, [], (err, rows) => { res.json(rows || []); }); });

app.post('/api/deposit/request', (req, res) => {
    db.run(`INSERT INTO deposits (user_name, sender_name, amount, status, date) VALUES (?, ?, ?, '대기', ?)`, [req.body.userName, req.body.senderName, req.body.amount, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); });
});
app.get('/api/admin/deposits', (req, res) => { db.all(`SELECT * FROM deposits WHERE status = '대기'`, [], (err, rows) => { res.json(rows || []); }); });
app.post('/api/admin/deposit/approve/direct', (req, res) => {
    db.serialize(() => {
        db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [req.body.amount, req.body.userName]);
        db.run(`UPDATE deposits SET status = '승인_직접증액' WHERE id = ?`, [req.body.depositId]);
        res.json({ success: true });
    });
});
app.post('/api/admin/deposit/approve/qr', (req, res) => {
    const { depositId, userName, amount, issuer } = req.body;
    const checkId = 'META_QR_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6).toUpperCase();
    const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
    const date = new Date().toLocaleString('ko-KR');
    const signature = generateECCInverseSignature(checkId, secretKey, amount);

    db.serialize(() => {
        db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`, [checkId, amount, issuer, secretKey, signature, date]);
        db.run(`UPDATE deposits SET status = '승인_QR수표출하' WHERE id = ?`, [depositId]);
        const chatRoom = `room_support_${userName}_이재준`; // 고객센터 통일
        const qrPayload = `[META_QR]${checkId}|${secretKey}|${signature}`;
        db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`, [chatRoom, issuer, qrPayload, date], () => {
            res.json({ success: true });
            io.to(chatRoom).emit('receive_message', { roomId: chatRoom, sender: issuer, message: qrPayload, date });
        });
    });
});

app.post('/api/withdraw', (req, res) => {
    db.serialize(() => {
        db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [req.body.amount, req.body.name]);
        db.run(`INSERT INTO withdrawals (name, amount, status, date) VALUES (?, ?, '완료', ?)`, [req.body.name, req.body.amount, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); });
    });
});

app.post('/api/check/issue', (req, res) => {
    const { issuer, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "한도 부족" });
        const checkId = 'META_QR_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6).toUpperCase();
        const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
        const signature = generateECCInverseSignature(checkId, secretKey, amount);
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, eccSignature, is_used, date) VALUES (?, ?, ?, ?, ?, 0, ?)`, [checkId, amount, issuer, secretKey, signature, new Date().toLocaleString('ko-KR')], () => {
                res.json({ success: true, checkId, secretKey, signature });
            });
        });
    });
});
app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId, secretKey, signature } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`; let params = [checkId];
    if (secretKey && !checkId) { query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`; params = [secretKey]; }

    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "유효하지 않은 번호입니다" });
        if (signature && !verifyECCInverseSignature(row.id, row.secretKey, row.amount, signature)) return res.status(401).json({ error: "ECC 검증 실패" });
        db.serialize(() => {
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [row.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            res.json({ success: true, amount: row.amount });
        });
    });
});

app.post('/api/products/encrypt-build', (req, res) => {
    const { name, price, seller, storeId, description, thumbnail, encryptedPayload } = req.body;
    const pid = 'PRD_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    db.run(`INSERT INTO products (id, storeId, type, name, description, price, seller, thumbnail, encryptedPayload) VALUES (?, ?, 'html_enc', ?, ?, ?, ?, ?, ?)`,
        [pid, storeId, name, description, price, seller, thumbnail, encryptedPayload], () => { res.json({ success: true, id: pid }); });
});
app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => { res.json(rows || []); }); });
app.get('/api/products/active', (req, res) => { 
    // 공개 상태인 상점의 상품만 필터링 출력
    db.all(`SELECT p.* FROM products p JOIN stores s ON p.storeId = s.id WHERE s.status = 'active' ORDER BY p.id DESC`, [], (err, rows) => { res.json(rows || []); }); 
});
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => { res.json(row || {}); }); });

app.post('/api/product/edit', (req, res) => { db.run(`UPDATE products SET name = ?, price = ? WHERE id = ?`, [req.body.name, req.body.price, req.body.id], () => { res.json({ success: true }); }); });
app.post('/api/product/delete', (req, res) => { db.run(`DELETE FROM products WHERE id = ?`, [req.body.id], () => { res.json({ success: true }); }); });

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "자산 범위 초과" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, new Date().toLocaleString('ko-KR')], () => { res.json({ success: true }); });
        });
    });
});

app.post('/api/favorite/toggle', (req, res) => {
    db.get(`SELECT * FROM favorite_stores WHERE userName = ? AND targetStore = ?`, [req.body.userName, req.body.targetStore], (err, row) => {
        if(row) { db.run(`DELETE FROM favorite_stores WHERE id = ?`, [row.id], () => res.json({ success: true })); } 
        else { db.run(`INSERT INTO favorite_stores (userName, targetStore) VALUES (?, ?)`, [req.body.userName, req.body.targetStore], () => res.json({ success: true })); }
    });
});
app.get('/api/favorites/:userName', (req, res) => { db.all(`SELECT targetStore FROM favorite_stores WHERE userName = ?`, [req.params.userName], (err, rows) => { res.json(rows ? rows.map(r => r.targetStore) : []); }); });
app.get('/api/chat/:roomId', (req, res) => { db.all(`SELECT * FROM chats WHERE roomId = ? ORDER BY id ASC`, [req.params.roomId], (err, rows) => res.json(rows || [])); });

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        const txs = await new Promise(r => db.all(`SELECT * FROM transactions WHERE buyer=? OR seller=?`, [name, name], (e, rows) => r(rows||[])));
        const dps = await new Promise(r => db.all(`SELECT * FROM deposits WHERE user_name=?`, [name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));
        
        let history = [];
        txs.forEach(t => history.push({ type: t.buyer === name ? '자산구매' : '자산판매', date: t.date, amount: t.amount, productName: t.productName, seller: t.seller }));
        dps.forEach(d => history.push({ type: `입금요청(${d.status})`, date: d.date, amount: d.amount, seller: '어드민결재' }));
        wds.forEach(w => history.push({ type: '출금완료', date: w.date, amount: w.amount, seller: '지정계좌' }));
        
        history.sort((a,b) => new Date(b.date) - new Date(a.date)); res.json(history);
    } catch(e) { res.json([]); }
});

io.on('connection', (socket) => {
    socket.on('join_room', (roomId) => { socket.join(roomId); });
    socket.on('send_message', (data) => { db.run(`INSERT INTO chats (roomId, sender, message, date) VALUES (?, ?, ?, ?)`, [data.roomId, data.sender, data.message, new Date().toLocaleString('ko-KR')], () => { io.to(data.roomId).emit('receive_message', data); }); });
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[GITHUB SYSTEM V2] CORE BOUND ON PORT ${PORT}`); });
