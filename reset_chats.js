// 💬 채팅 히스토리 초기화 (1회성) — Earth 서버에서 `node reset_chats.js` 로 실행.
//   지우는 대상: chats(메시지 전체) + chat_rooms(대화방 목록) + chat_uploads/ 폴더(첨부 원본 파일).
//   보존: users/friends/products/transactions/stores 등 나머지는 그대로.
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const DB_PATH = path.join(__dirname, 'earth_database_master.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'chat_uploads');

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) { console.error('❌ DB 열기 실패:', err.message); process.exit(1); }
});

db.serialize(() => {
    db.run('DELETE FROM chats', function (e) {
        if (e) console.error('chats 삭제 오류:', e.message);
        else console.log(`✅ chats 메시지 ${this.changes}건 삭제`);
    });
    db.run('DELETE FROM chat_rooms', function (e) {
        if (e) console.log('ℹ️ chat_rooms 없음/스킵:', e.message);
        else console.log(`✅ chat_rooms ${this.changes}건 삭제`);
    });
    // 자동 증가 id 초기화(선택) — sqlite_sequence가 있을 때만
    db.run("DELETE FROM sqlite_sequence WHERE name IN ('chats','chat_rooms')", () => {});
    db.close(() => {
        // 첨부 원본 파일 폴더 비우기
        try {
            if (fs.existsSync(UPLOAD_DIR)) {
                let n = 0;
                for (const f of fs.readdirSync(UPLOAD_DIR)) {
                    try { fs.rmSync(path.join(UPLOAD_DIR, f), { force: true, recursive: true }); n++; } catch (_) {}
                }
                console.log(`✅ chat_uploads 첨부파일 ${n}개 삭제`);
            } else {
                console.log('ℹ️ chat_uploads 폴더 없음(아직 첨부 없음) — 스킵');
            }
        } catch (e) { console.error('chat_uploads 정리 오류:', e.message); }
        console.log('🎉 채팅 초기화 완료. 서버를 재시작하세요.');
    });
});
