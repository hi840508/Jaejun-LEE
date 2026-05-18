const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

// =========================================================
// ★ 직전 코드에서 실수로 누락되었던 프론트엔드 화면 연결 코드입니다! ★
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
// =========================================================

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = 4000;

const db = new sqlite3.Database(path.join(__dirname, 'commerce_final_ultimate.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT, bank TEXT, account TEXT, balance INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS products (id TEXT PRIMARY KEY, type TEXT, name TEXT, description TEXT, price INTEGER, seller TEXT, filePath TEXT, originalPayload TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, buyer TEXT, seller TEXT, productName TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, roomId TEXT, sender TEXT, message TEXT, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS qr_checks (id TEXT PRIMARY KEY, amount INTEGER, issuer TEXT, secretKey TEXT, is_used INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, amount INTEGER, date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS favorite_stores (id INTEGER PRIMARY KEY AUTOINCREMENT, userName TEXT, targetStore TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, amount INTEGER, bank TEXT, account TEXT, status TEXT, date TEXT)`);
});

app.post('/api/auth', (req, res) => {
    const { name, password, bank, account } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, row) => {
        if (row) {
            if (row.password !== password) return res.status(401).json({ error: "비밀번호 불일치" });
            return res.json(row);
        } else {
            const initialBalance = 10000;
            db.run(`INSERT INTO users (name, password, bank, account, balance) VALUES (?, ?, ?, ?, ?)`,
                [name, password, bank || '미지정은행', account || '000-00', initialBalance], (err) => {
                    return res.json({ name, bank, account, balance: initialBalance });
                });
        }
    });
});

app.get('/api/users/:name', (req, res) => {
    db.get(`SELECT balance FROM users WHERE name = ?`, [req.params.name], (err, row) => { res.json(row || { balance: 0 }); });
});

app.post('/api/transfer', (req, res) => {
    const { sender, receiver, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [sender], (err, sRow) => {
        if (!sRow || sRow.balance < amount) return res.status(400).json({ error: "한도 부족" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, sender]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, receiver]);
            const date = new Date().toLocaleString('ko-KR');
            db.run(`INSERT INTO transfers (sender, receiver, amount, date) VALUES (?, ?, ?, ?)`, [sender, receiver, amount, date], () => {
                res.json({ success: true });
            });
        });
    });
});

app.post('/api/withdraw', (req, res) => {
    const { name, amount } = req.body;
    db.get(`SELECT * FROM users WHERE name = ?`, [name], (err, user) => {
        if(!user || user.balance < amount) return res.status(400).json({ error: "출금 가용 자산 부족" });
        const date = new Date().toLocaleString('ko-KR');
        db.run(`INSERT INTO withdrawals (name, amount, bank, account, status, date) VALUES (?, ?, ?, ?, '대기', ?)`,
            [name, amount, user.bank, user.account, date], () => {
                res.json({ success: true });
            });
    });
});

app.get('/api/admin/withdrawals', (req, res) => {
    db.all(`SELECT * FROM withdrawals WHERE status = '대기'`, [], (err, rows) => { res.json(rows || []); });
});

app.post('/api/admin/withdraw/approve', (req, res) => {
    const { id } = req.body;
    db.get(`SELECT * FROM withdrawals WHERE id = ?`, [id], (err, w) => {
        if(!w) return res.status(404).json({ error: "명세 누락" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [w.amount, w.name]);
            db.run(`UPDATE withdrawals SET status = '완료' WHERE id = ?`, [id], () => {
                res.json({ success: true });
            });
        });
    });
});

app.post('/api/check/issue', (req, res) => {
    const { issuer, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [issuer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "발행 자용한도 부족" });
        const checkId = 'META_QR_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6).toUpperCase();
        const secretKey = Math.floor(100000 + Math.random() * 900000).toString();
        const date = new Date().toLocaleString('ko-KR');

        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, issuer]);
            db.run(`INSERT INTO qr_checks (id, amount, issuer, secretKey, is_used, date) VALUES (?, ?, ?, ?, 0, ?)`,
                [checkId, amount, issuer, secretKey, date], () => {
                    res.json({ success: true, checkId, secretKey });
                });
        });
    });
});

app.post('/api/check/redeem', (req, res) => {
    const { redeemer, checkId, secretKey } = req.body;
    let query = `SELECT * FROM qr_checks WHERE id = ? AND is_used = 0`;
    let params = [checkId];

    if (secretKey) {
        query = `SELECT * FROM qr_checks WHERE secretKey = ? AND is_used = 0`;
        params = [secretKey];
    }

    db.get(query, params, (err, row) => {
        if (!row) return res.status(404).json({ error: "이미 소진되었거나 원장 내역이 없는 무효한 보안 키/QR입니다." });
        db.serialize(() => {
            db.run(`UPDATE qr_checks SET is_used = 1 WHERE id = ?`, [row.id]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [row.amount, redeemer]);
            res.json({ success: true, amount: row.amount });
        });
    });
});

app.post('/api/products/encrypt-build', (req, res) => {
    const { name, price, seller, description, originalPayload } = req.body;
    const pid = 'PRD_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    
    db.run(`INSERT INTO products (id, type, name, description, price, seller, filePath, originalPayload) VALUES (?, 'html_enc', ?, ?, ?, ?, '', ?)`,
        [pid, name, description, price, seller, originalPayload], (err) => {
            res.json({ success: true, id: pid });
        });
});

app.get('/api/products', (req, res) => { db.all(`SELECT * FROM products ORDER BY id DESC`, [], (err, rows) => { res.json(rows || []); }); });
app.get('/api/product/detail/:id', (req, res) => { db.get(`SELECT * FROM products WHERE id = ?`, [req.params.id], (err, row) => { res.json(row || {}); }); });
app.get('/api/stores', (req, res) => { db.all(`SELECT DISTINCT seller FROM products`, [], (err, rows) => { res.json(rows ? rows.map(r => r.seller) : []); }); });

app.post('/api/product/edit', (req, res) => {
    const { id, name, price } = req.body;
    db.run(`UPDATE products SET name = ?, price = ? WHERE id = ?`, [name, price, id], () => { res.json({ success: true }); });
});

app.post('/api/product/delete', (req, res) => {
    const { id } = req.body;
    db.run(`DELETE FROM products WHERE id = ?`, [id], () => { res.json({ success: true }); });
});

app.post('/api/buy', (req, res) => {
    const { buyer, seller, productId, productName, amount } = req.body;
    db.get(`SELECT balance FROM users WHERE name = ?`, [buyer], (err, row) => {
        if (!row || row.balance < amount) return res.status(400).json({ error: "자산 정산 한도 초과" });
        db.serialize(() => {
            db.run(`UPDATE users SET balance = balance - ? WHERE name = ?`, [amount, buyer]);
            db.run(`UPDATE users SET balance = balance + ? WHERE name = ?`, [amount, seller]);
            const date = new Date().toLocaleString('ko-KR');
            db.run(`INSERT INTO transactions (buyer, seller, productName, amount, date) VALUES (?, ?, ?, ?, ?)`, [buyer, seller, productName, amount, date], () => {
                res.json({ success: true });
            });
        });
    });
});

app.post('/api/favorite/toggle', (req, res) => {
    const { userName, targetStore } = req.body;
    db.get(`SELECT * FROM favorite_stores WHERE userName = ? AND targetStore = ?`, [userName, targetStore], (err, row) => {
        if(row) {
            db.run(`DELETE FROM favorite_stores WHERE id = ?`, [row.id], () => res.json({ success: true }));
        } else {
            db.run(`INSERT INTO favorite_stores (userName, targetStore) VALUES (?, ?)`, [userName, targetStore], () => res.json({ success: true }));
        }
    });
});

app.get('/api/favorites/:userName', (req, res) => {
    db.all(`SELECT targetStore FROM favorite_stores WHERE userName = ?`, [req.params.userName], (err, rows) => {
        res.json(rows ? rows.map(r => r.targetStore) : []);
    });
});

app.get('/api/transactions/:name', async (req, res) => {
    const name = req.params.name;
    try {
        const txs = await new Promise(r => db.all(`SELECT * FROM transactions WHERE buyer=? OR seller=?`, [name, name], (e, rows) => r(rows||[])));
        const tfs = await new Promise(r => db.all(`SELECT * FROM transfers WHERE sender=? OR receiver=?`, [name, name], (e, rows) => r(rows||[])));
        const wds = await new Promise(r => db.all(`SELECT * FROM withdrawals WHERE name=?`, [name], (e, rows) => r(rows||[])));
        
        let history = [];
        txs.forEach(t => history.push({ type: t.buyer === name ? '자산구매' : '자산판매', date: t.date, amount: t.amount, productName: t.productName, seller: t.seller }));
        tfs.forEach(t => history.push({ type: t.sender === name ? 'P2P송금출금' : 'P2P송금입금', date: t.date, amount: t.amount, seller: t.receiver }));
        wds.forEach(w => history.push({ type: `출금신청(${w.status})`, date: w.date, amount: w.amount, seller: '정산대기' }));
        
        history.sort((a,b) => new Date(b.date) - new Date(a.date));
        res.json(history);
    } catch(e) { res.json([]); }
});

server.listen(PORT, '0.0.0.0', () => { console.log(`[GITHUB SYSTEM V1] CORE BOUND ON PORT ${PORT}`); });
