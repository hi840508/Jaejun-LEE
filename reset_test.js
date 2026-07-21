// 🧪 테스트 초기화 스크립트 — 거래성 데이터 + 채팅 삭제 + 모든 잔액 0.
//   유지: users(회원, 잔액만 0으로) · stores(상점) · products(상품) · settings · favorite_stores · friends · product_reviews
//   삭제: transactions · transfers · deposits · withdrawals · product_orders · refund_requests · tax_invoices · qr_checks · chats · chat_rooms
//   실행:  cd ~/ray-bank && node reset_test.js     (라이브 DB에 직접 작용 — 반드시 백업 후 실행)
var sqlite3 = require('sqlite3');
var db = new sqlite3.Database('./earth_database_master.sqlite');
var dels = ['transactions','transfers','deposits','withdrawals','product_orders','refund_requests','tax_invoices','qr_checks','chats','chat_rooms'];
db.serialize(function () {
  dels.forEach(function (t) {
    db.run('DELETE FROM ' + t, function (e) { console.log(e ? ('ERR ' + t + ': ' + e.message) : ('deleted ' + t)); });
  });
  db.run('UPDATE users SET balance = 0', function (e) { console.log(e ? ('ERR balance: ' + e.message) : ('balance_reset_rows=' + this.changes)); });
  var cnt = ['users','stores','products','transactions','chats','product_orders','tax_invoices','transfers','deposits','withdrawals','refund_requests','qr_checks','chat_rooms'];
  cnt.forEach(function (t) {
    db.get('SELECT count(*) c FROM ' + t, function (e, r) { console.log('count ' + t + '=' + (r ? r.c : ('ERR:' + (e && e.message)))); });
  });
  db.get('SELECT count(*) z FROM users WHERE IFNULL(balance,0) != 0', function (e, r) { console.log('users_nonzero_balance=' + (r ? r.z : '?')); });
});
setTimeout(function () { db.close(function () { process.exit(0); }); }, 5000);
