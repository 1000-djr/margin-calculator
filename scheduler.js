/**
 * scheduler.js
 * 매일 04:00, 16:00 (KST) 에 모든 연동 사용자의 도매처 상품을 자동 동기화
 */

const cron = require('node-cron');
const { pool } = require('./db');
const { syncSupplierProductsForUser } = require('./api');

async function runAllUsersSync() {
  const { rows } = await pool.query(
    'SELECT DISTINCT user_id FROM wholesale_suppliers WHERE api_linked=true AND api_type IS NOT NULL'
  );
  console.log(`[sync] ${new Date().toISOString()} 자동 동기화 시작 — 대상 ${rows.length}명`);
  for (const { user_id } of rows) {
    try {
      const r = await syncSupplierProductsForUser(user_id);
      console.log(`[sync] user ${user_id}: ${r.synced}건 (${r.suppliers.map(s => `${s.name} ${s.ok ? s.count+'건' : '실패:'+s.error}`).join(', ')})`);
    } catch(e) {
      console.error(`[sync] user ${user_id} 실패:`, e.message);
    }
  }
  console.log('[sync] 자동 동기화 완료');
}

function start() {
  // 매일 04:00, 16:00 KST
  cron.schedule('0 4,16 * * *', runAllUsersSync, { timezone: 'Asia/Seoul' });
  console.log('[scheduler] 도매처 자동 동기화 등록: 매일 04:00, 16:00 KST');
}

module.exports = { start, runAllUsersSync };
