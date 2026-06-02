/**
 * profit.js
 * 공통 수익 계산 함수 — api.js(수익분석 탭)와 admin.js(어드민 집계)에서 공유
 *
 * 수식: 순이익 = 실매출(쿠폰후) - 수수료(11.66%) - 원가(B2B이력) - 실광고비 - 부가세(면세)
 *       부가세(면세) = -(수수료/11) - (광고비원가/11)
 */

const { pool } = require('./db');

/**
 * calculateProfit(userId, startDate, endDate, groupBy)
 *
 * @param {number}      userId    - users.id (필수)
 * @param {string|null} startDate - YYYY-MM-DD 또는 null
 * @param {string|null} endDate   - YYYY-MM-DD 또는 null
 * @param {string}      groupBy   - 'day' | 'week' | 'month'  (기본: 'month')
 * @returns {Promise<{ summary, by_period }>}
 */
async function calculateProfit(userId, startDate, endDate, groupBy = 'month', discountMode = null) {
  if (!['day', 'week', 'month'].includes(groupBy)) groupBy = 'month';

  // discount_mode가 전달되지 않으면 DB에서 조회
  if (!discountMode) {
    const { rows: modeRows } = await pool.query(
      'SELECT discount_mode FROM users WHERE id=$1',
      [userId]
    );
    discountMode = modeRows[0]?.discount_mode || 'coupon';
  }

  const params = [userId, startDate || null, endDate || null];

  // ── 할인 계산 서브쿼리 (discount_mode에 따라 분기) ────────────────────────────
  const discountSubquery = discountMode === 'fixed'
    ? `
      SELECT fd.discount_amount
      FROM fixed_discounts fd
      WHERE fd.user_id = o.user_id
        AND fd.option_id = o.option_id
        AND o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
        AND fd.start_date <= (
          CASE WHEN o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}'
               THEN TO_TIMESTAMP(SUBSTRING(o.order_date,1,19), 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'Asia/Seoul'
               ELSE (TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')::TIMESTAMP + INTERVAL '23 hours 59 minutes 59 seconds') AT TIME ZONE 'Asia/Seoul'
          END
        )
        AND (fd.end_date IS NULL
          OR fd.end_date >= (
            CASE WHEN o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}'
                 THEN TO_TIMESTAMP(SUBSTRING(o.order_date,1,19), 'YYYY-MM-DD HH24:MI:SS') AT TIME ZONE 'Asia/Seoul'
                 ELSE TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')::TIMESTAMP AT TIME ZONE 'Asia/Seoul'
            END
          )
        )
      ORDER BY fd.start_date DESC
      LIMIT 1`
    : `
      SELECT c.discount_amount
      FROM coupons c
      WHERE c.user_id = o.user_id
        AND c.option_ids @> jsonb_build_array(o.option_id)
        AND o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
        AND (c.start_at IS NULL
          OR SUBSTRING(o.order_date,1,10)
             >= TO_CHAR(c.start_at AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD'))
        AND (c.end_at IS NULL
          OR SUBSTRING(o.order_date,1,10)
             <= TO_CHAR(c.end_at AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD'))
      ORDER BY c.discount_amount DESC, c.coupon_id DESC NULLS LAST
      LIMIT 1`;

  // ── 공통 order_detail CTE 조각 (SQL 재사용) ─────────────────────────────────
  const ORDER_DETAIL_CTE = `
    order_detail AS (
      SELECT
        o.quantity,
        o.payment_amount + o.shipping_fee                 AS gross_sale,
        GREATEST(
          o.payment_amount + o.shipping_fee
          - COALESCE((${discountSubquery}
            ), 0),
          0
        )                                                 AS net_sale,
        COALESCE(
          o.override_cost_price::NUMERIC,
          (
            SELECT bp.cost
            FROM product_name_mapping pnm
            JOIN b2b_products b2bp
              ON b2bp.user_id = pnm.user_id
             AND b2bp.name    = pnm.b2b_name
             AND b2bp.unit    = pnm.b2b_unit
            JOIN b2b_prices bp
              ON bp.user_id        = pnm.user_id
             AND bp.b2b_product_id = b2bp.id
             AND (bp.start_date IS NULL
               OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                   AND bp.start_date
                       <= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
             AND (bp.end_date IS NULL
               OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                   AND bp.end_date
                       >= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
            WHERE pnm.user_id = o.user_id
              AND (
                (pnm.option_id IS NOT NULL AND pnm.option_id = o.option_id)
                OR
                (pnm.option_id IS NULL AND pnm.registered_name = o.product_name
                 AND pnm.option_name = COALESCE(o.option_name, ''))
              )
            ORDER BY (pnm.option_id IS NOT NULL) DESC, bp.start_date DESC NULLS LAST
            LIMIT 1
          ),
          0
        )                                                 AS unit_cost
      FROM orders o
      WHERE o.user_id = $1
        AND o.is_excluded = FALSE
        AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) >= $2)
        AND ($3::text IS NULL OR SUBSTRING(o.order_date,1,10) <= $3)
    )
  `;

  // ── 전체 합계 ────────────────────────────────────────────────────────────────
  const { rows: sRows } = await pool.query(`
    WITH
    ${ORDER_DETAIL_CTE},
    excluded_cnt AS (
      SELECT
        COUNT(*) FILTER (WHERE is_excluded = TRUE)::INTEGER AS cnt,
        COUNT(*) FILTER (WHERE exclusion_type = 'fake_order')::INTEGER AS fake_order_count,
        COUNT(*) FILTER (WHERE exclusion_type = 'return')::INTEGER AS return_count,
        COUNT(*) FILTER (WHERE exclusion_type = 'other')::INTEGER AS other_count
      FROM orders
      WHERE user_id = $1
        AND ($2::text IS NULL OR SUBSTRING(order_date,1,10) >= $2)
        AND ($3::text IS NULL OR SUBSTRING(order_date,1,10) <= $3)
    ),
    order_agg AS (
      SELECT
        COUNT(*)::INTEGER                        AS total_orders,
        SUM(gross_sale)::BIGINT                  AS revenue_before,
        SUM(net_sale)::BIGINT                    AS revenue_after,
        (SUM(net_sale) * 0.1166)::NUMERIC(14,2)  AS commission,
        SUM(unit_cost * quantity)::NUMERIC(14,2)  AS total_cost
      FROM order_detail
    ),
    ad_agg AS (
      SELECT
        COALESCE(SUM(actual_ad_cost), 0)::NUMERIC(14,2) AS actual_ad_cost,
        COALESCE(SUM(ad_cost),        0)::NUMERIC(14,2) AS ad_cost_raw
      FROM ad_reports
      WHERE user_id = $1
        AND ($2::text IS NULL OR report_date >= $2)
        AND ($3::text IS NULL OR report_date <= $3)
    ),
    return_costs AS (
      SELECT
        COALESCE(SUM(return_shipping_fee), 0)::BIGINT       AS total_return_shipping,
        COALESCE(SUM(return_cost),         0)::NUMERIC(14,2) AS total_return_cost
      FROM returns
      WHERE user_id = $1
        AND record_type = 'return'
        AND ($2::text IS NULL OR REPLACE(LEFT(COALESCE(received_at,''),10),'.', '-') >= $2)
        AND ($3::text IS NULL OR REPLACE(LEFT(COALESCE(received_at,''),10),'.', '-') <= $3)
    )
    SELECT
      oa.total_orders,
      ec.cnt              AS excluded_count,
      ec.fake_order_count,
      ec.return_count,
      ec.other_count,
      oa.revenue_before,
      oa.revenue_after,
      oa.commission,
      oa.total_cost,
      aa.actual_ad_cost,
      aa.ad_cost_raw,
      rc.total_return_shipping,
      rc.total_return_cost
    FROM order_agg oa
    CROSS JOIN ad_agg       aa
    CROSS JOIN excluded_cnt ec
    CROSS JOIN return_costs rc
  `, params);

  const s              = sRows[0] || {};
  const commission     = parseFloat(s.commission)          || 0;
  const adRaw          = parseFloat(s.ad_cost_raw)         || 0;
  const actualAd       = parseFloat(s.actual_ad_cost)      || 0;
  const revAfter       = parseInt(s.revenue_after)         || 0;
  const cost           = parseFloat(s.total_cost)          || 0;
  const tax            = -(commission / 11) - (adRaw / 11);
  const returnShipping = parseInt(s.total_return_shipping) || 0;
  const returnCost     = parseFloat(s.total_return_cost)   || 0;

  // ── 트래픽 비용 ─────────────────────────────────────────────────────────────
  let trafficCost = 0;
  try {
    const { rows: tRows } = await pool.query(`
      SELECT COALESCE(SUM(
        GREATEST(0,
          LEAST(end_date::date, COALESCE($3::date, '9999-12-31'::date))
          - GREATEST(start_date::date, COALESCE($2::date, '0001-01-01'::date))
          + 1
        ) *
        (slot_count * cost_per_slot * CASE WHEN vat_included THEN 1.0 ELSE 1.1 END)
        / GREATEST(1, end_date::date - start_date::date + 1)
      ), 0)::NUMERIC(14,2) AS traffic_cost
      FROM traffic_slots
      WHERE user_id = $1
        AND start_date::date <= COALESCE($3::date, '9999-12-31'::date)
        AND end_date::date   >= COALESCE($2::date, '0001-01-01'::date)
    `, params);
    trafficCost = Math.round(parseFloat(tRows[0]?.traffic_cost) || 0);
  } catch(e) {
    console.warn('[profit] traffic_slots 쿼리 스킵:', e.message);
  }

  const summary = {
    total_orders:     s.total_orders     || 0,
    excluded_count:   s.excluded_count   || 0,
    fake_order_count: s.fake_order_count || 0,
    return_count:     s.return_count     || 0,
    other_count:      s.other_count      || 0,
    revenue_before: parseInt(s.revenue_before) || 0,
    revenue_after:  revAfter,
    commission:     Math.round(commission),
    total_cost:     Math.round(cost),
    actual_ad_cost: Math.round(actualAd),
    ad_cost_raw:    Math.round(adRaw),
    traffic_cost:          trafficCost,
    total_return_shipping: returnShipping,
    total_return_cost:     Math.round(returnCost),
    net_profit:            Math.round(revAfter - commission - cost - actualAd - tax - trafficCost - returnShipping - returnCost),
  };

  // ── 기간별 집계 ──────────────────────────────────────────────────────────────
  // groupBy 값은 위에서 whitelist 검증 완료 → SQL 삽입 안전
  let orderPeriodExpr, adPeriodExpr;
  if (groupBy === 'month') {
    orderPeriodExpr = `SUBSTRING(o.order_date, 1, 7)`;
    adPeriodExpr    = `SUBSTRING(report_date, 1, 7)`;
  } else if (groupBy === 'week') {
    orderPeriodExpr = `TO_CHAR(TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD'), 'IYYY-"W"IW')`;
    adPeriodExpr    = `TO_CHAR(TO_DATE(report_date,'YYYY-MM-DD'), 'IYYY-"W"IW')`;
  } else {
    orderPeriodExpr = `SUBSTRING(o.order_date, 1, 10)`;
    adPeriodExpr    = `report_date`;
  }

  const { rows: pRows } = await pool.query(`
    WITH
    order_detail AS (
      SELECT
        ${orderPeriodExpr}                                AS period_key,
        o.quantity,
        o.payment_amount + o.shipping_fee                 AS gross_sale,
        GREATEST(
          o.payment_amount + o.shipping_fee
          - COALESCE((${discountSubquery}
            ), 0),
          0
        )                                                 AS net_sale,
        COALESCE(
          o.override_cost_price::NUMERIC,
          (
            SELECT bp.cost
            FROM product_name_mapping pnm
            JOIN b2b_products b2bp
              ON b2bp.user_id = pnm.user_id
             AND b2bp.name    = pnm.b2b_name
             AND b2bp.unit    = pnm.b2b_unit
            JOIN b2b_prices bp
              ON bp.user_id        = pnm.user_id
             AND bp.b2b_product_id = b2bp.id
             AND (bp.start_date IS NULL
               OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                   AND bp.start_date
                       <= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
             AND (bp.end_date IS NULL
               OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                   AND bp.end_date
                       >= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
            WHERE pnm.user_id = o.user_id
              AND (
                (pnm.option_id IS NOT NULL AND pnm.option_id = o.option_id)
                OR
                (pnm.option_id IS NULL AND pnm.registered_name = o.product_name
                 AND pnm.option_name = COALESCE(o.option_name, ''))
              )
            ORDER BY (pnm.option_id IS NOT NULL) DESC, bp.start_date DESC NULLS LAST
            LIMIT 1
          ),
          0
        )                                                 AS unit_cost
      FROM orders o
      WHERE o.user_id = $1
        AND o.is_excluded = FALSE
        AND o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
        AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) >= $2)
        AND ($3::text IS NULL OR SUBSTRING(o.order_date,1,10) <= $3)
    ),
    period_orders AS (
      SELECT
        period_key,
        COUNT(*)::INTEGER                        AS orders,
        SUM(gross_sale)::BIGINT                  AS revenue_before,
        SUM(net_sale)::BIGINT                    AS revenue_after,
        (SUM(net_sale) * 0.1166)::NUMERIC(14,2)  AS commission,
        SUM(unit_cost * quantity)::NUMERIC(14,2)  AS total_cost
      FROM order_detail
      GROUP BY period_key
    ),
    period_ads AS (
      SELECT
        ${adPeriodExpr}                                   AS period_key,
        SUM(ad_cost)::NUMERIC(14,2)                       AS ad_cost_raw,
        SUM(actual_ad_cost)::NUMERIC(14,2)                AS actual_ad_cost
      FROM ad_reports
      WHERE user_id = $1
        AND ($2::text IS NULL OR report_date >= $2)
        AND ($3::text IS NULL OR report_date <= $3)
      GROUP BY 1
    )
    SELECT
      COALESCE(po.period_key, pa.period_key)  AS period,
      COALESCE(po.orders,         0)          AS orders,
      COALESCE(po.revenue_before, 0)          AS revenue_before,
      COALESCE(po.revenue_after,  0)          AS revenue_after,
      COALESCE(po.commission,     0)          AS commission,
      COALESCE(po.total_cost,     0)          AS total_cost,
      COALESCE(pa.ad_cost_raw,    0)          AS ad_cost_raw,
      COALESCE(pa.actual_ad_cost, 0)          AS actual_ad_cost
    FROM period_orders po
    FULL OUTER JOIN period_ads pa ON pa.period_key = po.period_key
    ORDER BY 1
  `, params);

  const by_period = pRows.map(r => {
    const comm  = parseFloat(r.commission)     || 0;
    const adR   = parseFloat(r.ad_cost_raw)    || 0;
    const actAd = parseFloat(r.actual_ad_cost) || 0;
    const rev   = parseInt(r.revenue_after)    || 0;
    const cst   = parseFloat(r.total_cost)     || 0;
    const t     = -(comm / 11) - (adR / 11);
    return {
      period:         r.period,
      orders:         r.orders || 0,
      revenue_before: parseInt(r.revenue_before) || 0,
      revenue_after:  rev,
      commission:     Math.round(comm),
      total_cost:     Math.round(cst),
      actual_ad_cost: Math.round(actAd),
      ad_cost_raw:    Math.round(adR),
      net_profit:     Math.round(rev - comm - cst - actAd - t),
    };
  });

  // ── 상품별 집계 ──────────────────────────────────────────────────────────────
  const { rows: prodRows } = await pool.query(`
    WITH
    order_detail AS (
      SELECT
        o.option_id,
        o.product_name,
        o.option_name,
        o.quantity,
        o.payment_amount + o.shipping_fee                 AS gross_sale,
        GREATEST(
          o.payment_amount + o.shipping_fee
          - COALESCE((${discountSubquery}
            ), 0),
          0
        )                                                 AS net_sale,
        COALESCE(
          o.override_cost_price::NUMERIC,
          (
            SELECT bp.cost
            FROM product_name_mapping pnm
            JOIN b2b_products b2bp
              ON b2bp.user_id = pnm.user_id
             AND b2bp.name    = pnm.b2b_name
             AND b2bp.unit    = pnm.b2b_unit
            JOIN b2b_prices bp
              ON bp.user_id        = pnm.user_id
             AND bp.b2b_product_id = b2bp.id
             AND (bp.start_date IS NULL
               OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                   AND bp.start_date
                       <= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
             AND (bp.end_date IS NULL
               OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                   AND bp.end_date
                       >= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
            WHERE pnm.user_id = o.user_id
              AND (
                (pnm.option_id IS NOT NULL AND pnm.option_id = o.option_id)
                OR
                (pnm.option_id IS NULL AND pnm.registered_name = o.product_name
                 AND pnm.option_name = COALESCE(o.option_name, ''))
              )
            ORDER BY (pnm.option_id IS NOT NULL) DESC, bp.start_date DESC NULLS LAST
            LIMIT 1
          ),
          0
        )                                                 AS unit_cost
      FROM orders o
      WHERE o.user_id = $1
        AND o.is_excluded = FALSE
        AND o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
        AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) >= $2)
        AND ($3::text IS NULL OR SUBSTRING(o.order_date,1,10) <= $3)
    ),
    product_orders AS (
      SELECT
        option_id,
        product_name,
        option_name,
        SUM(quantity)::INTEGER                       AS qty,
        SUM(gross_sale)::BIGINT                      AS revenue_before,
        SUM(net_sale)::BIGINT                        AS revenue_after,
        (SUM(net_sale) * 0.1166)::NUMERIC(14,2)      AS commission,
        SUM(unit_cost * quantity)::NUMERIC(14,2)     AS total_cost
      FROM order_detail
      GROUP BY option_id, product_name, option_name
    ),
    product_ads AS (
      SELECT
        option_id,
        -- 광고보고서의 대표 상품명 (주문이 없는 광고-only 행 식별용)
        MAX(NULLIF(TRIM(product_name), '')) AS ad_product_name,
        SUM(ad_cost)::NUMERIC(14,2)        AS ad_cost_raw,
        SUM(actual_ad_cost)::NUMERIC(14,2) AS actual_ad_cost
      FROM ad_reports
      WHERE user_id = $1
        AND ($2::text IS NULL OR report_date >= $2)
        AND ($3::text IS NULL OR report_date <= $3)
      GROUP BY option_id
    )
    SELECT
      COALESCE(po.option_id,      pa.option_id) AS option_id,
      -- 주문 없는 광고-only 행: 광고보고서 상품명 → "광고비만 발생 (옵션ID: …)" 순으로 fallback
      COALESCE(
        NULLIF(TRIM(po.product_name), ''),
        NULLIF(TRIM(pa.ad_product_name), ''),
        CASE WHEN pa.option_id IS NOT NULL
             THEN '광고비만 발생 (옵션ID: ' || pa.option_id || ')'
             ELSE '' END
      )                                         AS product_name,
      COALESCE(po.option_name,    '')           AS option_name,
      COALESCE(po.qty,            0)            AS qty,
      COALESCE(po.revenue_before, 0)            AS revenue_before,
      COALESCE(po.revenue_after,  0)            AS revenue_after,
      COALESCE(po.commission,     0)            AS commission,
      COALESCE(po.total_cost,     0)            AS total_cost,
      COALESCE(pa.ad_cost_raw,    0)            AS ad_cost_raw,
      COALESCE(pa.actual_ad_cost, 0)            AS actual_ad_cost,
      -- 광고-only 행 여부 플래그
      (po.option_id IS NULL)                    AS ad_only
    FROM product_orders po
    FULL OUTER JOIN product_ads pa ON pa.option_id = po.option_id
    ORDER BY COALESCE(NULLIF(TRIM(po.product_name),''), NULLIF(TRIM(pa.ad_product_name),''), ''),
             COALESCE(po.option_name, '')
  `, params);

  function cleanAdProductName(raw) {
    if (!raw || !raw.includes(',')) return raw;
    const parts = raw.split(',').map(s => s.trim()).filter(Boolean);
    const baseName = parts[0];
    const rest = [...new Set(parts.slice(1))]; // 중복 제거 (1개,1개 → 1개 / 5kg,5kg → 5kg)
    const count = rest.find(t => /^\d+\s*개$/.test(t)) || '';
    const unit  = rest.find(t => t !== count) || '';
    const tail  = [unit, count].filter(Boolean).join(' ');
    return tail ? `${baseName} (${tail})` : baseName;
  }

  const by_product = prodRows.map(r => {
    const comm   = parseFloat(r.commission)     || 0;
    const adRaw  = parseFloat(r.ad_cost_raw)    || 0;
    const actAd  = parseFloat(r.actual_ad_cost) || 0;
    const rev    = parseInt(r.revenue_after)    || 0;
    const cost   = parseFloat(r.total_cost)     || 0;
    const qty    = parseInt(r.qty)              || 0;
    const tax    = -(comm / 11) - (adRaw / 11);
    const net    = Math.round(rev - comm - cost - actAd - tax);
    return {
      option_id:      r.option_id,
      product_name:   (r.ad_only === true || r.ad_only === 't') ? cleanAdProductName(r.product_name) : r.product_name,
      option_name:    r.option_name,
      qty,
      revenue_before: parseInt(r.revenue_before) || 0,
      revenue_after:  rev,
      commission:     Math.round(comm),
      total_cost:     Math.round(cost),
      actual_ad_cost: Math.round(actAd),
      ad_cost_raw:    Math.round(adRaw),
      net_profit:     net,
      margin_rate:    rev > 0 ? parseFloat((net / rev * 100).toFixed(2)) : 0,
      ad_only:        r.ad_only === true || r.ad_only === 't', // 광고비만 발생 (주문 없음)
    };
  });

  return { summary, by_period, by_product };
}

module.exports = { calculateProfit };
