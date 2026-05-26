/**
 * api.js
 * B2B 사이트 등록, 최신 가격 조회, 수동 크롤링 트리거 REST API
 * + 사용자 인증 정보 및 개인 데이터 저장 API
 */

const express = require('express');
const router  = express.Router();
const { pool } = require('./db');
const { calculateProfit } = require('./profit');

let crawlStatus = { running: false, lastRun: null, lastResult: null };

// ─── 인증 미들웨어 ────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: '로그인이 필요합니다.' });
  next();
}

// ─── 현재 유저 정보 ───────────────────────────────────────────────────────────
router.get('/auth/me', (req, res) => {
  res.json(req.user || null);
});

// ─── 유저 데이터 키-값 저장소 ─────────────────────────────────────────────────
// key: platforms | suppliers | b2bProducts | history | shortcuts
router.get('/user/data/:key', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT value FROM user_data WHERE user_id = $1 AND key = $2',
      [req.user.id, req.params.key]
    );
    res.json(rows[0]?.value ?? null);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/user/data/:key', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO user_data (user_id, key, value)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [req.user.id, req.params.key, JSON.stringify(req.body)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 사이트 등록 목록 ─────────────────────────────────────────────
router.get('/sites', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM b2b_sites ORDER BY id');
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/sites', async (req, res) => {
  const { name, url, login_url, username_env, password_env } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'name과 url은 필수입니다.' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO b2b_sites (name, url, login_url, username_env, password_env)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [name, url, login_url || null, username_env || null, password_env || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/sites/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM b2b_sites WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 최신 가격 조회 ───────────────────────────────────────────────
// 각 상품의 가장 최근 가격 1건씩 반환
router.get('/prices/latest', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT ON (ph.product_id)
        ph.product_id,
        ph.supply_price,
        ph.sale_price,
        ph.stock,
        ph.tax_type,
        ph.shipping_fee,
        ph.crawled_at,
        p.name        AS product_name,
        p.unit,
        p.image_url,
        p.external_id,
        s.id          AS site_id,
        s.name        AS site_name
      FROM price_history ph
      JOIN products p ON p.id = ph.product_id
      JOIN b2b_sites s ON s.id = p.site_id
      ORDER BY ph.product_id, ph.crawled_at DESC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 특정 상품의 가격 이력
router.get('/prices/history/:productId', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT price, crawled_at FROM price_history
       WHERE product_id=$1 ORDER BY crawled_at DESC LIMIT 30`,
      [req.params.productId]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 수동 크롤링 트리거 ───────────────────────────────────────────
router.post('/crawl', async (req, res) => {
  if (crawlStatus.running) {
    return res.status(409).json({ error: '이미 크롤링 중입니다.' });
  }
  res.json({ ok: true, message: '크롤링을 시작합니다.' });

  // 응답 후 백그라운드 실행
  crawlStatus.running = true;
  const { runAll } = require('./crawler');
  runAll()
    .then(result => {
      crawlStatus.lastRun    = new Date().toISOString();
      crawlStatus.lastResult = result;
    })
    .catch(err => {
      crawlStatus.lastResult = { error: err.message };
    })
    .finally(() => {
      crawlStatus.running = false;
    });
});

router.get('/crawl/status', (req, res) => {
  res.json(crawlStatus);
});

// ─── 주문서 ───────────────────────────────────────────────────────────────────
router.get('/orders/summary', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        TO_CHAR(MAX(created_at) AT TIME ZONE 'Asia/Seoul', 'YYYY-MM-DD HH24:MI') AS last_uploaded,
        (SELECT order_date FROM orders
          WHERE user_id = $1
          ORDER BY REPLACE(LEFT(order_date, 10), '.', '-') DESC, order_date DESC
          LIMIT 1)                                                                 AS latest_order_date
      FROM orders
      WHERE user_id = $1
    `, [req.user.id]);
    res.json(rows[0] || { last_uploaded: null, latest_order_date: null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/orders', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date, exclude_excluded } = req.query;
    console.log(`[GET /orders] user=${req.user.id} start=${start_date||'none'} end=${end_date||'none'} exclude_excluded=${exclude_excluded||'false'}`);
    let q = 'SELECT * FROM orders WHERE user_id=$1';
    const params = [req.user.id];
    if (exclude_excluded === 'true') q += ' AND (is_excluded IS NULL OR is_excluded = false)';
    // order_date는 VARCHAR(50), 'YYYY-MM-DD HH:mm' 또는 'YYYY.MM.DD' 혼용 → 앞 10자리 추출 후 점을 하이픈으로 변환해 비교
    if (start_date) {
      params.push(start_date);
      q += ` AND REPLACE(LEFT(order_date, 10), '.', '-') >= $${params.length}`;
    }
    if (end_date) {
      params.push(end_date);
      q += ` AND REPLACE(LEFT(order_date, 10), '.', '-') <= $${params.length}`;
    }
    q += ' ORDER BY order_date DESC, created_at DESC';
    const { rows } = await pool.query(q, params);
    console.log(`[GET /orders] 결과=${rows.length}건`);
    res.json(rows.map(r => ({
      '번호':                r.id,
      '주문번호':            r.order_number,
      '묶음배송번호':        r.bundle_number,
      '주문일':              r.order_date,
      '등록상품명':          r.product_name,
      '등록옵션명':          r.option_name,
      '노출상품명(옵션명)':  r.display_name,
      '노출상품ID':          r.display_product_id,
      '옵션ID':              r.option_id,
      '결제액':              r.payment_amount,
      '배송비':              r.shipping_fee,
      '구매수(수량)':        r.quantity,
      '옵션판매가(판매단가)': r.unit_price,
      '택배사':              r.courier,
      '운송장번호':          r.tracking_number,
      '출고일':              r.shipped_date,
      '배송완료일':          r.delivered_date,
      '구매확정일자':        r.confirmed_date,
      '결제위치':            r.payment_location,
      '배송유형':            r.delivery_type,
      '구매자':              r.buyer_masked,
      '구매자전화번호':      '',
      '수취인이름':          r.recipient_name_masked,
      '수취인전화번호':      r.recipient_phone_masked,
      '우편번호':            '',
      '수취인 주소':         r.recipient_address_masked,
      'is_excluded':         r.is_excluded || false,
      'exclusion_type':      r.exclusion_type || 'normal',
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/orders/exclude-bulk', requireAuth, async (req, res) => {
  const { order_numbers, is_excluded, exclusion_type = 'normal' } = req.body;
  if (!Array.isArray(order_numbers) || !order_numbers.length)
    return res.status(400).json({ error: 'order_numbers 배열 필수' });
  const VALID = ['normal','fake_order','return','other','cancel'];
  const safeType = VALID.includes(exclusion_type) ? exclusion_type : 'normal';
  try {
    const result = await pool.query(
      `UPDATE orders SET is_excluded=$1, exclusion_type=$2
       WHERE user_id=$3 AND order_number = ANY($4::varchar[])`,
      [is_excluded !== false, safeType, req.user.id, order_numbers]
    );
    res.json({ updated: result.rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/orders/:orderNumber/exclude', requireAuth, async (req, res) => {
  const { is_excluded, exclusion_type = 'normal' } = req.body;
  const VALID = ['normal','fake_order','return','other','cancel'];
  const safeType = VALID.includes(exclusion_type) ? exclusion_type : 'normal';
  try {
    await pool.query(
      'UPDATE orders SET is_excluded=$1, exclusion_type=$2 WHERE order_number=$3 AND user_id=$4',
      [!!is_excluded, safeType, req.params.orderNumber, req.user.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/orders/bulk-update', requireAuth, async (req, res) => {
  const { ids, is_excluded, exclusion_type = 'normal' } = req.body;
  if (!Array.isArray(ids) || !ids.length)
    return res.status(400).json({ error: 'ids 배열 필수' });
  const VALID = ['normal','fake_order','return','other','cancel'];
  const safeType = VALID.includes(exclusion_type) ? exclusion_type : 'normal';
  try {
    const { rowCount } = await pool.query(
      `UPDATE orders SET is_excluded=$1, exclusion_type=$2
       WHERE user_id=$3 AND id = ANY($4::int[])`,
      [!!is_excluded, safeType, req.user.id, ids]
    );
    res.json({ updated: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/orders/bulk', requireAuth, async (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  if (!items.length) return res.json({ inserted: 0 });
  console.log(`[orders/bulk] user=${req.user.id} items=${items.length}`);

  const CHUNK = 500;
  let inserted = 0;
  try {
    for (let start = 0; start < items.length; start += CHUNK) {
      const chunk = items.slice(start, start + CHUNK);
      for (const o of chunk) {
        const r = await pool.query(
          `INSERT INTO orders
           (user_id,order_number,bundle_number,order_date,product_name,option_name,
            display_name,display_product_id,option_id,payment_amount,shipping_fee,
            quantity,unit_price,courier,tracking_number,shipped_date,delivered_date,
            confirmed_date,payment_location,delivery_type,buyer_masked,
            recipient_name_masked,recipient_phone_masked,recipient_address_masked)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
           ON CONFLICT (user_id, order_number) DO NOTHING`,
          [
            req.user.id,
            o['주문번호'] || '',
            o['묶음배송번호'] || '',
            o['주문일'] || '',
            o['등록상품명'] || '',
            o['등록옵션명'] || '',
            o['노출상품명(옵션명)'] || o['노출상품명'] || '',
            o['노출상품ID'] || '',
            o['옵션ID'] || '',
            parseInt(o['결제액']) || 0,
            parseInt(o['배송비']) || 0,
            parseInt(o['구매수(수량)']) || parseInt(o['구매수량']) || 1,
            parseInt(o['옵션판매가(판매단가)']) || parseInt(o['옵션판매가']) || 0,
            o['택배사'] || '',
            o['운송장번호'] || '',
            o['출고일'] || '',
            o['배송완료일'] || '',
            o['구매확정일자'] || '',
            o['결제위치'] || '',
            o['배송유형'] || '',
            o['구매자'] || '',
            o['수취인이름'] || '',
            o['수취인전화번호'] || '',
            o['수취인 주소'] || o['수취인주소'] || '',
          ]
        );
        if (r.rowCount > 0) inserted++;
      }
      console.log(`[orders/bulk] 청크 ${start + 1}~${Math.min(start + CHUNK, items.length)} 처리 완료`);
    }
    console.log(`[orders/bulk] 완료: 삽입=${inserted} / 전체=${items.length}`);
    res.json({ inserted });
  } catch(e) {
    console.error('[orders/bulk] DB 오류:', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.delete('/orders', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE user_id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/orders/:id', requireAuth, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM orders WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: '주문을 찾을 수 없습니다.' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 광고보고서 ───────────────────────────────────────────────────────────────
router.get('/ad-reports/summary', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        TO_CHAR(MAX(created_at) AT TIME ZONE 'Asia/Seoul', 'YYYY-MM-DD HH24:MI') AS last_uploaded,
        MAX(report_date)                                                           AS latest_report_date
      FROM ad_reports
      WHERE user_id = $1
    `, [req.user.id]);
    res.json(rows[0] || { last_uploaded: null, latest_report_date: null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/ad-reports', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    console.log(`[GET /ad-reports] user=${req.user.id} start=${start_date||'none'} end=${end_date||'none'}`);
    let q = 'SELECT * FROM ad_reports WHERE user_id=$1';
    const params = [req.user.id];
    if (start_date) { params.push(start_date); q += ` AND report_date >= $${params.length}`; }
    if (end_date)   { params.push(end_date);   q += ` AND report_date <= $${params.length}`; }
    q += ' ORDER BY report_date DESC, created_at DESC';
    const { rows } = await pool.query(q, params);
    console.log(`[GET /ad-reports] 결과=${rows.length}건`);
    res.json(rows.map(r => {
      // raw_data가 있으면 원본 그대로 반환, 없으면 구 컬럼으로 재구성
      if (r.raw_data) {
        return {
          ...r.raw_data,
          '실광고비':    parseFloat(r.actual_ad_cost),
          'ad_placement': r.ad_placement,
        };
      }
      return {
        '날짜':                  r.report_date,
        '캠페인 ID':             r.campaign_id,
        '캠페인명':              r.campaign_name,
        '광고그룹':              r.ad_group,
        '광고집행 상품명':       r.product_name,
        '광고집행 옵션ID':       r.option_id,
        '키워드':                r.keyword,
        '노출수':                r.impressions,
        '클릭수':                r.clicks,
        '광고비':                r.ad_cost,
        '실광고비':              r.actual_ad_cost,
        'ad_placement':          r.ad_placement,
        '총 주문수(1일)':        r.orders_1d,
        '총 판매수량(1일)':      r.quantity_1d,
        '총 전환매출액(1일)':    r.revenue_1d,
        '총 주문수(14일)':       r.orders_14d,
        '총 판매수량(14일)':     r.quantity_14d,
        '총 전환매출액(14일)':   r.revenue_14d,
      };
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function formatAdDate(val) {
  // Date 객체
  if (val instanceof Date) return val.toISOString().split('T')[0];
  const s = String(val ?? '').trim();
  // 정수형 YYYYMMDD (숫자 8자리)
  if (/^\d{8}$/.test(s)) return s.slice(0, 4) + '-' + s.slice(4, 6) + '-' + s.slice(6, 8);
  return s;
}

function safeInt(v)   { const n = parseInt(v);   return isNaN(n) ? null : n; }
function safeFloat(v) { const n = parseFloat(v); return isNaN(n) ? null : n; }
function safeStr(v)   { return (v == null || v === '') ? null : String(v); }

router.post('/ad-reports/bulk', requireAuth, async (req, res) => {
  const items  = Array.isArray(req.body) ? req.body : [];
  const userId = parseInt(req.user.id, 10);
  if (!items.length) return res.json({ inserted: 0, skipped: 0, failed: 0, total: 0 });

  // 첫 행 컬럼명 로그 → 실제 엑셀 헤더 확인용
  if (items[0]) {
    console.log(`[ad-reports/bulk] user=${userId} items=${items.length} 컬럼:`, Object.keys(items[0]).join(' | '));
  }

  const CHUNK = 500;
  let inserted = 0, skipped = 0, failed = 0;

  try {
  for (let start = 0; start < items.length; start += CHUNK) {
    const chunk = items.slice(start, start + CHUNK);
    for (const r of chunk) {
      try {
        // ③ raw_data: 원본 행 전체 무조건 저장
        const rawData = JSON.stringify(r);

        const productName = r['광고집행 상품명'] || r['광고집행상품명'] || '';
        const optionId    = r['광고집행 옵션ID'] || r['광고집행옵션ID'] || '';
        const adCost      = safeFloat(r['광고비']) ?? 0;

        // ② 노출지면: 실제 엑셀 컬럼명 '광고 노출 지면' 그대로 사용
        if (start === 0 && chunk.indexOf(r) === 0) console.log('[ad-reports] 광고 노출 지면 값(첫행):', r['광고 노출 지면']);
        const adPlacement = r['광고 노출 지면'] !== undefined ? r['광고 노출 지면'] : null;

        const result = await pool.query(
          `INSERT INTO ad_reports
           (user_id,report_date,campaign_id,campaign_name,ad_group,product_name,
            option_id,keyword,impressions,clicks,ad_cost,actual_ad_cost,
            orders_1d,quantity_1d,revenue_1d,orders_14d,quantity_14d,revenue_14d,
            raw_data,billing_type,sales_type,ad_type,ad_placement,click_rate,
            conv_product,conv_option_id,
            direct_orders_1d,indirect_orders_1d,direct_qty_1d,indirect_qty_1d,
            direct_rev_1d,indirect_rev_1d,
            direct_orders_14d,indirect_orders_14d,direct_qty_14d,indirect_qty_14d,
            direct_rev_14d,indirect_rev_14d,
            roas_total_1d,roas_direct_1d,roas_indirect_1d,
            roas_total_14d,roas_direct_14d,roas_indirect_14d,
            campaign_start,campaign_end,note)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                   $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,
                   $35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47)
           ON CONFLICT DO NOTHING`,
          [
            userId,                                                               // $1 ①
            formatAdDate(r['날짜'] ?? ''),                                       // $2
            safeStr(r['캠페인 ID'] || r['캠페인ID']),                            // $3
            safeStr(r['캠페인명']),                                               // $4
            safeStr(r['광고그룹']),                                               // $5
            safeStr(productName),                                                 // $6
            safeStr(optionId),                                                    // $7
            safeStr(r['키워드']) ?? '',                                           // $8
            safeInt(r['노출수'])   ?? 0,                                          // $9
            safeInt(r['클릭수'])   ?? 0,                                          // $10
            adCost,                                                               // $11
            Math.round(adCost * 1.1 * 100) / 100,                                // $12
            safeInt(r['총 주문수(1일)'])        ?? safeInt(r['총주문수(1일)'])        ?? 0, // $13
            safeInt(r['총 판매수량(1일)'])      ?? safeInt(r['총판매수량(1일)'])      ?? 0, // $14
            safeFloat(r['총 전환매출액(1일)'])  ?? safeFloat(r['총전환매출액(1일)'])  ?? 0, // $15
            safeInt(r['총 주문수(14일)'])       ?? safeInt(r['총주문수(14일)'])       ?? 0, // $16
            safeInt(r['총 판매수량(14일)'])     ?? safeInt(r['총판매수량(14일)'])     ?? 0, // $17
            safeFloat(r['총 전환매출액(14일)']) ?? safeFloat(r['총전환매출액(14일)']) ?? 0, // $18
            rawData,                                                              // $19 ③
            safeStr(r['과금 방식'] || r['과금방식']),                             // $20
            safeStr(r['판매방식']),                                               // $21
            safeStr(r['광고유형']),                                               // $22
            adPlacement,                                                          // $23 ②
            safeStr(r['클릭률']),                                                 // $24
            safeStr(r['광고전환매출발생 상품명'] || r['광고전환매출발생상품명']), // $25
            safeStr(r['광고전환매출발생 옵션ID'] || r['광고전환매출발생옵션ID']), // $26
            safeInt(r['직접 주문수(1일)'])        ?? safeInt(r['직접주문수(1일)'])        ?? 0, // $27
            safeInt(r['간접 주문수(1일)'])        ?? safeInt(r['간접주문수(1일)'])        ?? 0, // $28
            safeInt(r['직접 판매수량(1일)'])      ?? safeInt(r['직접판매수량(1일)'])      ?? 0, // $29
            safeInt(r['간접 판매수량(1일)'])      ?? safeInt(r['간접판매수량(1일)'])      ?? 0, // $30
            safeFloat(r['직접 전환매출액(1일)'])  ?? safeFloat(r['직접전환매출액(1일)'])  ?? 0, // $31
            safeFloat(r['간접 전환매출액(1일)'])  ?? safeFloat(r['간접전환매출액(1일)'])  ?? 0, // $32
            safeInt(r['직접 주문수(14일)'])       ?? safeInt(r['직접주문수(14일)'])       ?? 0, // $33
            safeInt(r['간접 주문수(14일)'])       ?? safeInt(r['간접주문수(14일)'])       ?? 0, // $34
            safeInt(r['직접 판매수량(14일)'])     ?? safeInt(r['직접판매수량(14일)'])     ?? 0, // $35
            safeInt(r['간접 판매수량(14일)'])     ?? safeInt(r['간접판매수량(14일)'])     ?? 0, // $36
            safeFloat(r['직접 전환매출액(14일)']) ?? safeFloat(r['직접전환매출액(14일)']) ?? 0, // $37
            safeFloat(r['간접 전환매출액(14일)']) ?? safeFloat(r['간접전환매출액(14일)']) ?? 0, // $38
            safeStr(r['총광고수익률(1일)']),    // $39
            safeStr(r['직접광고수익률(1일)']),  // $40
            safeStr(r['간접광고수익률(1일)']),  // $41
            safeStr(r['총광고수익률(14일)']),   // $42
            safeStr(r['직접광고수익률(14일)']), // $43
            safeStr(r['간접광고수익률(14일)']), // $44
            safeStr(r['캠페인 시작일'] || r['캠페인시작일']), // $45
            safeStr(r['캠페인 종료일'] || r['캠페인종료일']), // $46
            safeStr(r['비고']),                               // $47
          ]
        );
        if (result.rowCount > 0) inserted++;
        else skipped++;                                 // ⑤ DO NOTHING 건수
      } catch(rowErr) {
        failed++;
        // ④ 실패 시 에러 상세 + 행 정보 출력
        console.error(
          `[ad-reports/bulk] 행 저장 실패 user=${userId}`,
          `날짜=${r['날짜']} 옵션ID=${optionId} 지면=${r['광고 노출 지면']||r['노출지면']||''}`,
          rowErr.message
        );
      }
    }
    console.log(`[ad-reports/bulk] 청크 ${start + 1}~${Math.min(start + CHUNK, items.length)} 완료`);
  }
  } catch (fatalErr) {
    console.error(`[ad-reports/bulk] 치명적 오류 user=${userId}:`, fatalErr.message);
    return res.status(500).json({ error: fatalErr.message, inserted, skipped, failed, total: items.length });
  }

  console.log(`[ad-reports/bulk] 완료: user=${userId} 삽입=${inserted} / 중복스킵=${skipped} / 실패=${failed} / 전체=${items.length}`);
  res.json({ inserted, skipped, failed, total: items.length });
});

router.delete('/ad-reports', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM ad_reports WHERE user_id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 쿠폰 ────────────────────────────────────────────────────────────────────
function couponRow(r) {
  return {
    id:              r.id,
    coupon_id:       r.coupon_id ? String(r.coupon_id) : '',
    name:            r.name,
    discount_amount: parseFloat(r.discount_amount) || 0,
    start_at:        r.start_at ? r.start_at.toISOString() : '',
    end_at:          r.end_at   ? r.end_at.toISOString()   : '',
    option_ids:      Array.isArray(r.option_ids) ? r.option_ids : (r.option_ids || []),
  };
}

router.get('/coupons/summary', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT TO_CHAR(MAX(created_at) AT TIME ZONE 'Asia/Seoul', 'YYYY-MM-DD HH24:MI') AS last_registered
       FROM coupons WHERE user_id = $1`,
      [req.user.id]
    );
    res.json(rows[0] || { last_registered: null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/coupons', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM coupons WHERE user_id=$1 ORDER BY created_at ASC',
      [req.user.id]
    );
    res.json(rows.map(couponRow));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/coupons', requireAuth, async (req, res) => {
  const { coupon_id, name, discount_amount, start_at, end_at, option_ids } = req.body;
  if (!name) return res.status(400).json({ error: 'name 필수' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO coupons (user_id,coupon_id,name,discount_amount,start_at,end_at,option_ids)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [
        req.user.id,
        coupon_id || null,
        name,
        discount_amount || 0,
        start_at || null,
        end_at   || null,
        JSON.stringify(Array.isArray(option_ids) ? option_ids : []),
      ]
    );
    res.status(201).json(couponRow(rows[0]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/coupons/:id', requireAuth, async (req, res) => {
  const { coupon_id, name, discount_amount, start_at, end_at, option_ids } = req.body;
  if (!name) return res.status(400).json({ error: 'name 필수' });
  try {
    const { rows } = await pool.query(
      `UPDATE coupons
       SET coupon_id=$3, name=$4, discount_amount=$5, start_at=$6, end_at=$7, option_ids=$8
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [
        req.params.id,
        req.user.id,
        coupon_id || null,
        name,
        discount_amount || 0,
        start_at || null,
        end_at   || null,
        JSON.stringify(Array.isArray(option_ids) ? option_ids : []),
      ]
    );
    if (!rows.length) return res.status(404).json({ error: '쿠폰을 찾을 수 없습니다' });
    res.json(couponRow(rows[0]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/coupons/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM coupons WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 바로가기 ─────────────────────────────────────────────────────────────────
router.get('/shortcuts', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM shortcuts WHERE user_id=$1 ORDER BY created_at ASC',
      [req.user.id]
    );
    res.json(rows.map(r => ({ id: r.id, name: r.name, url: r.url })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/shortcuts', requireAuth, async (req, res) => {
  const { name, url } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'name, url 필수' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO shortcuts (user_id,name,url) VALUES ($1,$2,$3) RETURNING *',
      [req.user.id, name, url]
    );
    res.status(201).json({ id: rows[0].id, name: rows[0].name, url: rows[0].url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/shortcuts/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM shortcuts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 원가매칭 ─────────────────────────────────────────────────────────────────
router.get('/cost-mappings', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM cost_mapping WHERE user_id=$1 ORDER BY created_at ASC',
      [req.user.id]
    );
    res.json(rows.map(r => ({
      option_id:    r.option_id,
      product_name: r.product_name,
      supplier:     r.supplier,
      cost:         parseFloat(r.cost),
      tax_type:     r.tax_type,
      applied_date: r.applied_date,
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/cost-mappings/:optionId', requireAuth, async (req, res) => {
  const { supplierName, cost, taxType, productName } = req.body;
  const optionId = req.params.optionId;
  const today = new Date().toISOString().slice(0, 10);
  try {
    await pool.query(
      `INSERT INTO cost_mapping (user_id,option_id,product_name,supplier,cost,tax_type,applied_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id, option_id)
       DO UPDATE SET product_name=$3, supplier=$4, cost=$5, tax_type=$6, applied_date=$7`,
      [req.user.id, optionId, productName || '', supplierName || '', cost || 0, taxType || 'exempt', today]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/cost-mappings/:optionId', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM cost_mapping WHERE option_id=$1 AND user_id=$2', [req.params.optionId, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 광고 상품 매핑 (ad_option_id ↔ product_id) ──────────────────────────────
router.get('/ad-option-mappings', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT ad_option_id, product_id, product_name FROM ad_product_mapping WHERE user_id=$1 ORDER BY created_at',
      [req.user.id]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/ad-option-mappings', requireAuth, async (req, res) => {
  const { ad_option_id, product_id, product_name } = req.body;
  if (!ad_option_id) return res.status(400).json({ error: 'ad_option_id 필수' });
  try {
    await pool.query(
      `INSERT INTO ad_product_mapping (user_id, ad_option_id, product_id, product_name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, ad_option_id) DO UPDATE
         SET product_id = EXCLUDED.product_id, product_name = EXCLUDED.product_name`,
      [req.user.id, ad_option_id, product_id || '', product_name || '']
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/ad-option-mappings/:adOptionId', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM ad_product_mapping WHERE user_id=$1 AND ad_option_id=$2',
      [req.user.id, req.params.adOptionId]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── B2B 매입가 이력 ──────────────────────────────────────────────────────────
function b2bPriceRow(r) {
  return {
    id:            r.id,
    product_name:  r.product_name,
    unit:          r.unit || '',
    supplier_name: r.supplier_name,
    cost:          parseFloat(r.cost),
    start_date:    r.start_date ? r.start_date.toISOString().slice(0,10) : '',
    end_date:      r.end_date   ? r.end_date.toISOString().slice(0,10)   : '',
  };
}

async function upsertB2BProduct(userId, productName, unit, client) {
  const q = client || pool;
  const { rows } = await q.query(
    `INSERT INTO b2b_products (user_id,name,unit) VALUES ($1,$2,$3)
     ON CONFLICT (user_id,name,unit) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
    [userId, productName, unit || '']
  );
  return rows[0].id;
}

async function upsertB2BSupplier(userId, supplierName, client) {
  const q = client || pool;
  const { rows } = await q.query(
    `INSERT INTO b2b_suppliers (user_id,name) VALUES ($1,$2)
     ON CONFLICT (user_id,name) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
    [userId, supplierName]
  );
  return rows[0].id;
}

router.get('/b2b-prices/match', requireAuth, async (req, res) => {
  const { b2b_name, unit = '', order_date } = req.query;
  if (!b2b_name || !order_date) return res.status(400).json({ error: 'b2b_name, order_date 필수' });
  try {
    const { rows } = await pool.query(`
      SELECT bp.id, bp.cost,
             bp.start_date::text, bp.end_date::text,
             p.name AS product_name, p.unit,
             s.name AS supplier_name
      FROM b2b_prices bp
      JOIN b2b_products p ON p.id = bp.b2b_product_id
      JOIN b2b_suppliers s ON s.id = bp.supplier_id
      WHERE bp.user_id = $1
        AND p.name = $2
        AND ($3 = '' OR p.unit = $3)
        AND bp.start_date <= $4::date
        AND (bp.end_date IS NULL OR bp.end_date >= $4::date)
      ORDER BY bp.id DESC
      LIMIT 1
    `, [req.user.id, b2b_name, unit, order_date]);
    if (!rows.length) return res.json(null);
    res.json(b2bPriceRow(rows[0]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/b2b-prices', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT bp.id, bp.cost, bp.start_date, bp.end_date,
             p.name AS product_name, p.unit,
             s.name AS supplier_name
      FROM b2b_prices bp
      JOIN b2b_products p ON p.id = bp.b2b_product_id
      JOIN b2b_suppliers s ON s.id = bp.supplier_id
      WHERE bp.user_id = $1
      ORDER BY p.name, p.unit, bp.start_date DESC
    `, [req.user.id]);
    res.json(rows.map(b2bPriceRow));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/b2b-prices', requireAuth, async (req, res) => {
  const { product_name, unit, supplier_name, cost, start_date, end_date } = req.body;
  if (!product_name || !supplier_name || !cost || !start_date)
    return res.status(400).json({ error: 'product_name, supplier_name, cost, start_date 필수' });
  try {
    const productId  = await upsertB2BProduct(req.user.id, product_name, unit);
    const supplierId = await upsertB2BSupplier(req.user.id, supplier_name);
    const { rows } = await pool.query(
      `INSERT INTO b2b_prices (user_id,b2b_product_id,supplier_id,cost,start_date,end_date)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (user_id,b2b_product_id,supplier_id,start_date) DO NOTHING
       RETURNING id, cost, start_date, end_date`,
      [req.user.id, productId, supplierId, cost, start_date, end_date || null]
    );
    if (!rows.length) return res.status(409).json({ error: '동일 상품+공급처+시작일 중복' });
    res.status(201).json({ id: rows[0].id, product_name, unit: unit||'', supplier_name, cost: parseFloat(rows[0].cost), start_date: rows[0].start_date.toISOString().slice(0,10), end_date: rows[0].end_date ? rows[0].end_date.toISOString().slice(0,10) : '' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/b2b-prices/bulk', requireAuth, async (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  let inserted = 0, dupCount = 0;
  const errorRows = [];
  for (const item of items) {
    const { product_name, unit, supplier_name, cost, start_date, end_date } = item;
    if (!product_name || !supplier_name || !cost || !start_date) { errorRows.push(`skip: ${product_name}`); continue; }
    try {
      const productId  = await upsertB2BProduct(req.user.id, product_name, unit);
      const supplierId = await upsertB2BSupplier(req.user.id, supplier_name);
      const r = await pool.query(
        `INSERT INTO b2b_prices (user_id,b2b_product_id,supplier_id,cost,start_date,end_date)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (user_id,b2b_product_id,supplier_id,start_date) DO NOTHING`,
        [req.user.id, productId, supplierId, cost, start_date, end_date || null]
      );
      if (r.rowCount > 0) inserted++; else dupCount++;
    } catch(e) { errorRows.push(`${product_name}: ${e.message}`); }
  }
  res.json({ inserted, dupCount, errorRows });
});

router.put('/b2b-prices/:id', requireAuth, async (req, res) => {
  const { product_name, unit, supplier_name, cost, start_date, end_date } = req.body;
  if (!product_name || !supplier_name || !cost || !start_date)
    return res.status(400).json({ error: '필수값 누락' });
  try {
    const productId  = await upsertB2BProduct(req.user.id, product_name, unit);
    const supplierId = await upsertB2BSupplier(req.user.id, supplier_name);
    await pool.query(
      `UPDATE b2b_prices SET b2b_product_id=$3,supplier_id=$4,cost=$5,start_date=$6,end_date=$7
       WHERE id=$1 AND user_id=$2`,
      [req.params.id, req.user.id, productId, supplierId, cost, start_date, end_date || null]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/b2b-prices/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM b2b_prices WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// B2B 이력 기간 내 매핑된 주문 조회 (발주 조정용)
router.get('/b2b-prices/:id/orders', requireAuth, async (req, res) => {
  try {
    const { rows: priceRows } = await pool.query(`
      SELECT bp.id, bp.cost, bp.start_date, bp.end_date,
             p.name AS product_name, p.unit,
             s.name AS supplier_name
      FROM b2b_prices bp
      JOIN b2b_products p ON p.id = bp.b2b_product_id
      JOIN b2b_suppliers s ON s.id = bp.supplier_id
      WHERE bp.id = $1 AND bp.user_id = $2
    `, [req.params.id, req.user.id]);

    if (!priceRows.length) return res.status(404).json({ error: '이력을 찾을 수 없습니다' });
    const price = priceRows[0];

    // 상품명 매핑 조회 (b2b_name → registered_name 역매핑)
    const { rows: mappings } = await pool.query(`
      SELECT pnm.registered_name, pnm.option_name
      FROM product_name_mapping pnm
      JOIN b2b_products b2bp
        ON b2bp.user_id = pnm.user_id
       AND b2bp.name    = pnm.b2b_name
       AND b2bp.unit    = pnm.b2b_unit
      WHERE pnm.user_id = $1
        AND b2bp.name   = $2
        AND b2bp.unit   = $3
    `, [req.user.id, price.product_name, price.unit || '']);

    let orders = [];
    if (mappings.length > 0) {
      const startStr = price.start_date ? price.start_date.toISOString().slice(0, 10) : null;
      const endStr   = price.end_date   ? price.end_date.toISOString().slice(0, 10)   : null;

      // (registered_name, option_name) 쌍을 IN 조건으로 구성
      const pairs = mappings.map((m, i) =>
        `(o.product_name = $${4 + i * 2} AND o.option_name = $${5 + i * 2})`
      ).join(' OR ');
      const pairParams = mappings.flatMap(m => [m.registered_name, m.option_name]);

      const { rows: orderRows } = await pool.query(`
        SELECT o.id, o.order_number, o.order_date, o.product_name, o.option_name,
               o.quantity, o.override_cost_price, o.override_cost_note
        FROM orders o
        WHERE o.user_id = $1
          AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) >= $2)
          AND ($3::text IS NULL OR SUBSTRING(o.order_date,1,10) <= $3)
          AND (${pairs})
        ORDER BY o.order_date DESC, o.id DESC
      `, [req.user.id, startStr, endStr, ...pairParams]);

      orders = orderRows;
    }

    res.json({
      price: {
        id:            price.id,
        product_name:  price.product_name,
        unit:          price.unit,
        supplier_name: price.supplier_name,
        cost:          parseFloat(price.cost),
        start_date:    price.start_date ? price.start_date.toISOString().slice(0, 10) : null,
        end_date:      price.end_date   ? price.end_date.toISOString().slice(0, 10)   : null,
      },
      orders,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 주문 발주 조정 저장 (override_cost_price)
router.put('/orders/override-cost', requireAuth, async (req, res) => {
  const { order_ids, override_cost_price, override_cost_note } = req.body;
  if (!Array.isArray(order_ids) || !order_ids.length)
    return res.status(400).json({ error: 'order_ids 배열 필수' });
  const cost = override_cost_price != null ? parseInt(override_cost_price) : null;
  try {
    const { rowCount } = await pool.query(
      `UPDATE orders
          SET override_cost_price = $1,
              override_cost_note  = $2
        WHERE user_id = $3
          AND id = ANY($4::int[])`,
      [cost, override_cost_note || null, req.user.id, order_ids]
    );
    res.json({ updated: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── product-name-mappings ──────────────────────────────────────────────────────
router.get('/product-name-mappings', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM product_name_mapping WHERE user_id=$1 ORDER BY registered_name',
      [req.user.id]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/product-name-mappings', requireAuth, async (req, res) => {
  const { registered_name, option_name = '', b2b_name, b2b_unit = '' } = req.body;
  if (!registered_name || !b2b_name) return res.status(400).json({ error: '필수값 누락' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO product_name_mapping (user_id, registered_name, option_name, b2b_name, b2b_unit)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, registered_name, option_name)
         DO UPDATE SET b2b_name = EXCLUDED.b2b_name, b2b_unit = EXCLUDED.b2b_unit
       RETURNING *`,
      [req.user.id, registered_name, option_name, b2b_name, b2b_unit]
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/product-name-mappings/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM product_name_mapping WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 반품 관리 ────────────────────────────────────────────────────────────────
router.get('/returns/summary', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date, record_type } = req.query;
    let recordClause = '';
    if (record_type === 'return') {
      recordClause = `AND COALESCE(record_type, 'return') = 'return'`;
    } else if (record_type === 'cancel') {
      recordClause = `AND record_type = 'cancel'`;
    }
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)::INTEGER                                                        AS total_count,
        COALESCE(SUM(return_cost),0)::NUMERIC(14,2)                             AS total_cost,
        COALESCE(SUM(refund_amount),0)::BIGINT                                  AS total_refund,
        COUNT(*) FILTER (WHERE return_type='seller')::INTEGER                   AS seller_count,
        COUNT(*) FILTER (WHERE return_type='buyer')::INTEGER                    AS buyer_count,
        COUNT(*) FILTER (WHERE return_type='other')::INTEGER                    AS other_count,
        COUNT(*) FILTER (WHERE delivery_status='출고중지완료')::INTEGER          AS stop_complete_count,
        COUNT(*) FILTER (WHERE delivery_status='이미출고')::INTEGER             AS already_shipped_count,
        COUNT(*) FILTER (WHERE return_status='completed')::INTEGER              AS processed_complete_count,
        COUNT(*) FILTER (WHERE return_status='transferred')::INTEGER            AS processed_transfer_count,
        COUNT(*) FILTER (WHERE return_status IS NULL)::INTEGER                  AS pending_count
      FROM returns
      WHERE user_id = $1
        AND ($2::text IS NULL OR received_at IS NULL OR received_at >= $2)
        AND ($3::text IS NULL OR received_at IS NULL OR received_at <= $3)
        ${recordClause}
    `, [req.user.id, start_date || null, end_date || null]);
    res.json(rows[0] || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/returns', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date, return_type, record_type } = req.query;
    const params = [req.user.id, start_date || null, end_date || null];
    let typeClause = '';
    let recordClause = '';
    if (return_type && return_type !== 'all') {
      params.push(return_type);
      typeClause = `AND return_type = $${params.length}`;
    }
    if (record_type === 'return') {
      recordClause = `AND COALESCE(record_type, 'return') = 'return'`;
    } else if (record_type === 'cancel') {
      recordClause = `AND record_type = 'cancel'`;
    }
    const { rows } = await pool.query(`
      SELECT * FROM returns
      WHERE user_id = $1
        AND ($2::text IS NULL OR received_at IS NULL OR received_at >= $2)
        AND ($3::text IS NULL OR received_at IS NULL OR received_at <= $3)
        ${typeClause}
        ${recordClause}
      ORDER BY COALESCE(received_at, '') DESC, id DESC
    `, params);
    console.log(`[GET /returns] user=${req.user.id} record_type=${record_type||'all'} → ${rows.length}건`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/returns/bulk', requireAuth, async (req, res) => {
  const items = req.body;
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items 배열 필수' });

  // 첫 번째 raw_data 키 출력 (실제 쿠팡 컬럼명 확인용)
  const firstRaw = items[0]?.raw_data || {};
  console.log('[returns/bulk] raw_data 첫 번째 행 키:', Object.keys(firstRaw));

  let inserted = 0, skipped = 0;

  try {
    for (const r of items) {
      const raw = r.raw_data || {};

      const productName = raw['노출상품명'] || raw['상품명']  || r.product_name  || null;
      const optionName  = raw['옵션']       || raw['옵션명']  || r.option_name   || null;
      const orderNumber = raw['주문번호']   || r.order_number || null;

      console.log('[returns/bulk] productName:', productName, '| optionName:', optionName, '| orderNumber:', orderNumber);

      const result = await pool.query(`
        INSERT INTO returns (
          user_id, received_at, receipt_number, delivery_status, return_status,
          warehousing_status, warehousing_method, warehousing_tracking,
          product_name, option_name, quantity, return_reason,
          return_shipping_fee, shipping_fee_burden, refund_amount,
          recipient_masked, phone_masked, return_address_masked, collection_address_masked,
          order_number, expected_ship_date, warehousing_complete_date,
          return_complete_date, receipt_channel, option_id, raw_data
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26
        )
        ON CONFLICT (user_id, receipt_number) DO NOTHING
      `, [
        req.user.id,
        r.received_at                   || null,
        r.receipt_number,
        r.delivery_status               || null,
        r.return_status                 || null,
        r.warehousing_status            || null,
        r.warehousing_method            || null,
        r.warehousing_tracking          || null,
        productName,
        optionName,
        parseInt(r.quantity)            || 1,
        r.return_reason                 || null,
        parseInt(r.return_shipping_fee) || 0,
        r.shipping_fee_burden           || null,
        parseInt(r.refund_amount)       || 0,
        r.recipient_masked              || null,
        r.phone_masked                  || null,
        r.return_address_masked         || null,
        r.collection_address_masked     || null,
        orderNumber,
        r.expected_ship_date            || null,
        r.warehousing_complete_date     || null,
        r.return_complete_date          || null,
        r.receipt_channel               || null,
        r.option_id                     || null,
        r.raw_data ? JSON.stringify(r.raw_data) : null,
      ]);
      if (result.rowCount > 0) inserted++; else skipped++;
    }

    // INSERT 완료 후 주문번호 추출 → orders 반품 자동 미인식 처리
    const orderNumbers = items.map(r => (r.raw_data?.['주문번호'] || r.order_number || '')).filter(Boolean);
    console.log('[returns/bulk] orderNumbers:', orderNumbers);

    let ordersUpdated = 0;
    if (orderNumbers.length > 0) {
      const { rowCount } = await pool.query(
        `UPDATE orders
            SET is_excluded    = TRUE,
                exclusion_type = 'return'
          WHERE user_id = $1
            AND order_number = ANY($2)`,
        [req.user.id, orderNumbers]
      );
      ordersUpdated = rowCount;
      console.log('[returns/bulk] orders 반품 처리 완료:', ordersUpdated, '건');
    }

    res.json({ inserted, skipped, ordersUpdated });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 출고중지 엑셀 업로드
// 배송상태 분기:
//   '출고중지완료' → orders만 is_excluded=true, exclusion_type='cancel'
//   '이미출고'     → returns 행 삽입(record_type='cancel') + orders is_excluded=true, exclusion_type='cancel'
router.post('/cancel-shipments/bulk', requireAuth, async (req, res) => {
  const items = req.body;
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items 배열 필수' });

  let inserted = 0, skipped = 0, ordersUpdated = 0;
  const cancelOrderNumbers = [];

  console.log('[cancel-shipments/bulk] 수신 건수:', items.length);
  if (items[0]) {
    console.log('[cancel-shipments/bulk] 첫 번째 행 delivery_status:', items[0].delivery_status);
    console.log('[cancel-shipments/bulk] 첫 번째 행 receipt_number:', items[0].receipt_number);
    console.log('[cancel-shipments/bulk] 첫 번째 행 raw_data keys:', Object.keys(items[0].raw_data || {}));
  }

  try {
    for (const r of items) {
      const orderNumber = r.order_number || null;

      // 접수번호가 있는 건은 모두 returns 테이블에 저장 (배송상태 무관)
      if (r.receipt_number) {
        const result = await pool.query(`
          INSERT INTO returns (
            user_id, received_at, receipt_number, delivery_status,
            product_name, option_name, quantity, return_reason,
            recipient_masked, phone_masked,
            order_number, expected_ship_date, warehousing_complete_date,
            receipt_channel, option_id, record_type, raw_data
          ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'cancel',$16
          )
          ON CONFLICT (user_id, receipt_number) DO NOTHING
        `, [
          req.user.id,
          r.received_at              || null,
          r.receipt_number,
          r.delivery_status          || null,
          r.product_name             || null,
          r.option_name              || null,
          parseInt(r.quantity)       || 1,
          r.return_reason            || null,
          r.recipient_masked         || null,
          r.phone_masked             || null,
          orderNumber,
          r.expected_ship_date       || null,
          r.stop_complete_date       || null,
          r.receipt_channel          || null,
          r.option_id                || null,
          r.raw_data ? JSON.stringify(r.raw_data) : null,
        ]);
        if (result.rowCount > 0) inserted++; else skipped++;
      }
      // orders 제외 처리
      if (orderNumber) cancelOrderNumbers.push(orderNumber);
    }

    if (cancelOrderNumbers.length > 0) {
      const { rowCount } = await pool.query(
        `UPDATE orders
            SET is_excluded    = TRUE,
                exclusion_type = 'cancel'
          WHERE user_id = $1
            AND order_number = ANY($2)`,
        [req.user.id, cancelOrderNumbers]
      );
      ordersUpdated = rowCount;
    }

    res.json({ inserted, skipped, ordersUpdated });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 출고중지완료 처리
router.post('/cancel-shipments/:id/complete', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { rows } = await pool.query(
      'SELECT * FROM returns WHERE id=$1 AND user_id=$2 AND record_type=$3',
      [id, req.user.id, 'cancel']
    );
    if (!rows.length) return res.status(404).json({ error: '출고중지 건 없음' });
    const r = rows[0];

    await pool.query(
      `UPDATE returns SET return_status='completed' WHERE id=$1 AND user_id=$2`,
      [id, req.user.id]
    );

    let ordersUpdated = 0;
    if (r.order_number) {
      const { rowCount } = await pool.query(
        `UPDATE orders SET is_excluded=TRUE, exclusion_type='cancel'
          WHERE user_id=$1 AND order_number=$2`,
        [req.user.id, r.order_number]
      );
      ordersUpdated = rowCount;
    }

    res.json({ ok: true, ordersUpdated });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 이미출고 → 반품 이관
router.post('/cancel-shipments/:id/transfer', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { rows } = await pool.query(
      'SELECT * FROM returns WHERE id=$1 AND user_id=$2 AND record_type=$3',
      [id, req.user.id, 'cancel']
    );
    if (!rows.length) return res.status(404).json({ error: '출고중지 건 없음' });
    const r = rows[0];

    // 새 반품 행 삽입 (receipt_number 충돌 방지: 'TRF-{id}' 접두사)
    const newReceiptNumber = `TRF-${id}`;
    await pool.query(`
      INSERT INTO returns (
        user_id, received_at, receipt_number, product_name, option_name,
        quantity, option_id, order_number, record_type
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'return')
      ON CONFLICT (user_id, receipt_number) DO NOTHING
    `, [
      req.user.id,
      r.received_at   || null,
      newReceiptNumber,
      r.product_name  || null,
      r.option_name   || null,
      r.quantity      || 1,
      r.option_id     || null,
      r.order_number  || null,
    ]);

    // 원본 출고중지 건 상태 업데이트
    await pool.query(
      `UPDATE returns SET return_status='transferred' WHERE id=$1 AND user_id=$2`,
      [id, req.user.id]
    );

    // 주문 반품 처리
    let ordersUpdated = 0;
    if (r.order_number) {
      const { rowCount } = await pool.query(
        `UPDATE orders SET is_excluded=TRUE, exclusion_type='return'
          WHERE user_id=$1 AND order_number=$2`,
        [req.user.id, r.order_number]
      );
      ordersUpdated = rowCount;
    }

    res.json({ ok: true, ordersUpdated });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/returns', requireAuth, async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids 배열 필수' });
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM returns WHERE user_id=$1 AND id = ANY($2::int[])',
      [req.user.id, ids]
    );
    res.json({ deleted: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/returns/:id', requireAuth, async (req, res) => {
  const { restore_order } = req.body || {};
  try {
    // 삭제 전 주문번호 조회
    const { rows } = await pool.query(
      'SELECT order_number FROM returns WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: '반품 없음' });
    const orderNumber = rows[0].order_number;

    await pool.query(
      'DELETE FROM returns WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );

    let orderRestored = false;
    if (restore_order && orderNumber) {
      const { rowCount } = await pool.query(`
        UPDATE orders
           SET is_excluded    = FALSE,
               exclusion_type = 'normal'
         WHERE user_id = $1
           AND order_number = $2
           AND exclusion_type = 'return'
      `, [req.user.id, orderNumber]);
      orderRestored = rowCount > 0;
    }

    res.json({ deleted: 1, orderNumber, orderRestored });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/returns/:id/process', requireAuth, async (req, res) => {
  const VALID_TYPES = ['seller', 'buyer', 'other'];
  const { return_type, return_cost, process_memo } = req.body;
  const safeType = VALID_TYPES.includes(return_type) ? return_type : 'other';
  try {
    const { rows } = await pool.query(`
      UPDATE returns
         SET return_type  = $1,
             return_cost  = $2,
             process_memo = $3
       WHERE id = $4 AND user_id = $5
      RETURNING *
    `, [
      safeType,
      parseFloat(return_cost) || 0,
      process_memo || null,
      req.params.id,
      req.user.id,
    ]);
    if (!rows.length) return res.status(404).json({ error: '반품 없음' });
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 수익 분석 (백엔드 통합 계산) ────────────────────────────────────────────
router.get('/analytics', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date, group_by = 'month' } = req.query;
    const result = await calculateProfit(
      req.user.id,
      start_date || null,
      end_date   || null,
      group_by
    );
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 가구매 업체 마스터 ──────────────────────────────────────────────────────
router.get('/fake-vendors', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM fake_purchase_vendors WHERE user_id = $1 ORDER BY vendor_name',
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/fake-vendors', requireAuth, async (req, res) => {
  try {
    const { vendor_name, method, review_type, delivery_fee, process_fee, tax_rate, product_cost } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO fake_purchase_vendors
         (user_id, vendor_name, method, review_type, delivery_fee, process_fee, tax_rate, product_cost)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.id, vendor_name, method || '빈박스', review_type || '별점',
       delivery_fee || 0, process_fee || 0, tax_rate || 0, product_cost || 0]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.put('/fake-vendors/:id', requireAuth, async (req, res) => {
  try {
    const { vendor_name, method, review_type, delivery_fee, process_fee, tax_rate, product_cost } = req.body;
    const { rows } = await pool.query(
      `UPDATE fake_purchase_vendors
         SET vendor_name=$1, method=$2, review_type=$3,
             delivery_fee=$4, process_fee=$5, tax_rate=$6, product_cost=$7
       WHERE id=$8 AND user_id=$9 RETURNING *`,
      [vendor_name, method, review_type, delivery_fee, process_fee, tax_rate, product_cost,
       req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: '없음' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/fake-vendors/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM fake_purchase_vendors WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 가구매용 주문 조회 ──────────────────────────────────────────────────────
router.get('/fake-orders', requireAuth, async (req, res) => {
  try {
    const { order_date } = req.query;
    const { rows } = await pool.query(
      `SELECT id, order_number, product_name, option_name, quantity,
              payment_amount, shipping_fee,
              payment_amount + shipping_fee AS net_sale,
              exclusion_type
         FROM orders
        WHERE user_id = $1
          AND ($2::text IS NULL OR SUBSTRING(order_date,1,10) = $2)
          AND exclusion_type = 'fake_order'
        ORDER BY id DESC`,
      [req.user.id, order_date || null]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 가구매 진행 기록 ────────────────────────────────────────────────────────
router.get('/fake-records', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const { rows } = await pool.query(
      `SELECT r.*, v.vendor_name, v.method, v.review_type,
              v.delivery_fee, v.process_fee, v.tax_rate, v.product_cost
         FROM fake_purchase_records r
         JOIN fake_purchase_vendors v ON v.id = r.vendor_id
        WHERE r.user_id = $1
          AND ($2::text IS NULL OR r.proceed_date >= $2)
          AND ($3::text IS NULL OR r.proceed_date <= $3)
        ORDER BY r.proceed_date DESC, r.id DESC`,
      [req.user.id, start_date || null, end_date || null]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/fake-records', requireAuth, async (req, res) => {
  try {
    const { vendor_id, proceed_date, order_ids, total_cost } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO fake_purchase_records (user_id, vendor_id, proceed_date, order_ids, total_cost)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, vendor_id, proceed_date, JSON.stringify(order_ids || []), total_cost || 0]
    );

    // 해당 주문들의 exclusion_type을 fake_order로 설정
    if (order_ids && order_ids.length > 0) {
      await pool.query(
        `UPDATE orders SET is_excluded=TRUE, exclusion_type='fake_order'
          WHERE user_id=$1 AND id = ANY($2::int[])`,
        [req.user.id, order_ids]
      );
    }

    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/fake-records/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT order_ids FROM fake_purchase_records WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: '없음' });

    const orderIds = rows[0].order_ids || [];
    if (orderIds.length > 0) {
      await pool.query(
        `UPDATE orders SET is_excluded=FALSE, exclusion_type='normal'
          WHERE user_id=$1 AND id = ANY($2::int[]) AND exclusion_type='fake_order'`,
        [req.user.id, orderIds]
      );
    }

    await pool.query(
      'DELETE FROM fake_purchase_records WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 가구매 비용 합계 (수익분석용) ──────────────────────────────────────────
router.get('/fake-records/summary', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    const { rows } = await pool.query(
      `SELECT COALESCE(SUM(total_cost),0)::NUMERIC(14,2) AS total_fake_cost
         FROM fake_purchase_records
        WHERE user_id=$1
          AND ($2::text IS NULL OR proceed_date >= $2)
          AND ($3::text IS NULL OR proceed_date <= $3)`,
      [req.user.id, start_date || null, end_date || null]
    );
    res.json({ total_fake_cost: parseFloat(rows[0].total_fake_cost) || 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
