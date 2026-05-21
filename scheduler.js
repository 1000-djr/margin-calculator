/**
 * scheduler.js
 * 매일 새벽 6시에 모든 등록 B2B 사이트 자동 크롤링 실행
 */

const cron = require('node-cron');
const { runAll } = require('./crawler');

function start() {
  // 매일 06:00 (서버 로컬 시간 기준)
  cron.schedule('0 6 * * *', async () => {
    console.log(`[scheduler] ${new Date().toISOString()} 자동 크롤링 시작`);
    try {
      const results = await runAll();
      const total = results.reduce((s, r) => s + r.count, 0);
      console.log(`[scheduler] 완료 — 총 ${total}건 수집`);
    } catch (err) {
      console.error('[scheduler] 크롤링 오류:', err.message);
    }
  }, {
    timezone: 'Asia/Seoul',
  });

  console.log('[scheduler] 매일 06:00 (KST) 자동 크롤링 등록 완료');
}

module.exports = { start };
