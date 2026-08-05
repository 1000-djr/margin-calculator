/**
 * scheduler.js
 * 매일 04:00, 16:00 (KST) 에 모든 연동 사용자의 도매처 상품을 자동 동기화
 */

const cron = require('node-cron');
const { pool } = require('./db');
const { syncSupplierProductsForUser, fetchSupplierBalancesForUser, maskOldOrders } = require('./api');

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

async function runAllUsersBalance() {
  const { rows } = await pool.query(
    `SELECT DISTINCT user_id FROM wholesale_suppliers WHERE api_linked=true AND api_type='adminplus'`
  );
  console.log(`[balance] ${new Date().toISOString()} 잔액 자동 조회 — 대상 ${rows.length}명`);
  for (const { user_id } of rows) {
    try {
      const r = await fetchSupplierBalancesForUser(user_id);
      console.log(`[balance] user ${user_id}: ${r.map(x => x.ok ? x.supplier + ' ' + x.deposit : x.supplier + ' 실패').join(', ')}`);
    } catch(e) {
      console.error(`[balance] user ${user_id} 실패:`, e.message);
    }
  }
  console.log('[balance] 잔액 자동 조회 완료');
}

async function runMaskOldOrders() {
  try {
    const n = await maskOldOrders();
    console.log(`[mask] ${new Date().toISOString()} 14일 경과 주문 마스킹 ${n}건`);
  } catch(e) { console.error('[mask] 실패:', e.message); }
}

function start() {
  // 매일 04:00, 16:00 KST — 상품 동기화
  cron.schedule('0 4,16 * * *', runAllUsersSync, { timezone: 'Asia/Seoul' });
  console.log('[scheduler] 도매처 자동 동기화 등록: 매일 04:00, 16:00 KST');
  // 매일 09:00, 15:00 KST — 잔액 조회
  cron.schedule('0 9,15 * * *', runAllUsersBalance, { timezone: 'Asia/Seoul' });
  console.log('[scheduler] 도매처 잔액 자동 조회 등록: 매일 09:00, 15:00 KST');
  // 매일 03:30 KST — 14일 경과 주문 수령인 마스킹
  cron.schedule('30 3 * * *', runMaskOldOrders, { timezone: 'Asia/Seoul' });
  console.log('[scheduler] 14일 경과 주문 마스킹 등록: 매일 03:30 KST');
}

module.exports = { start, runAllUsersSync, runAllUsersBalance, runMaskOldOrders };
