/**
 * admin.js
 * 어드민 전용 라우터
 */

const express = require('express');
const path    = require('path');
const router  = express.Router();
const { pool } = require('./db');

// ─── 어드민 미들웨어 ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.user)          return res.status(401).json({ error: '로그인이 필요합니다.' });
  if (!req.user.is_admin) return res.status(403).json({ error: '어드민 권한이 필요합니다.' });
  next();
}

// ─── 어드민 페이지 ────────────────────────────────────────────────────────────
router.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── 전체 유저 목록 + 수익분석 완전 동일 수식 집계 ──────────────────────────
// 수식: 순이익 = 실매출 - 수수료(11.66%) - 원가(B2B이력) - 실광고비 - 부가세(면세)
// 파라미터: start_date, end_date (YYYY-MM-DD)
router.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const start = req.query.start_date || null;
    const end   = req.query.end_date   || null;

    const { rows } = await pool.query(`
      WITH order_detail AS (
        -- 주문별: 쿠폰할인 + B2B원가 (주문일 기준 이력 적용)
        SELECT
          o.user_id,
          o.id                                    AS order_id,
          o.quantity,
          o.payment_amount + o.shipping_fee       AS gross_sale,
          -- 실매출(쿠폰후): 쿠폰 기간 + 옵션ID 완전 매칭
          GREATEST(
            o.payment_amount + o.shipping_fee
            - COALESCE((
                SELECT SUM(c.discount_amount)
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
              ), 0),
            0
          ) AS net_sale,
          -- 단위원가: product_name_mapping → b2b_products → b2b_prices 이력
          COALESCE((
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
            WHERE pnm.user_id         = o.user_id
              AND pnm.registered_name = o.product_name
              AND pnm.option_name     = COALESCE(o.option_name, '')
            ORDER BY bp.start_date DESC NULLS LAST
            LIMIT 1
          ), 0) AS unit_cost
        FROM orders o
        WHERE o.is_excluded = FALSE
          AND ($1::text IS NULL OR SUBSTRING(o.order_date,1,10) >= $1)
          AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) <= $2)
      ),
      user_order_stats AS (
        SELECT
          user_id,
          COUNT(*)::INTEGER                        AS total_orders,
          SUM(gross_sale)::BIGINT                  AS revenue_before,
          SUM(net_sale)::BIGINT                    AS revenue_after,
          SUM(net_sale * 0.1166)::NUMERIC(14,2)    AS commission,
          SUM(unit_cost * quantity)::NUMERIC(14,2) AS total_cost
        FROM order_detail
        GROUP BY user_id
      ),
      user_ad_stats AS (
        SELECT
          user_id,
          SUM(actual_ad_cost)::NUMERIC(14,2) AS actual_ad_cost,
          SUM(ad_cost)::NUMERIC(14,2)        AS ad_cost_raw
        FROM ad_reports
        WHERE ($1::text IS NULL OR report_date >= $1)
          AND ($2::text IS NULL OR report_date <= $2)
        GROUP BY user_id
      )
      SELECT
        u.id, u.name, u.email, u.picture,
        u.status, u.is_admin, u.created_at, u.expires_at,
        COALESCE(os.total_orders,   0) AS total_orders,
        COALESCE(os.revenue_before, 0) AS revenue_before,
        COALESCE(os.revenue_after,  0) AS revenue_after,
        COALESCE(os.commission,     0) AS commission,
        COALESCE(os.total_cost,     0) AS total_cost,
        COALESCE(ar.actual_ad_cost, 0) AS actual_ad_cost,
        COALESCE(ar.ad_cost_raw,    0) AS ad_cost_raw
      FROM users u
      LEFT JOIN user_order_stats os ON os.user_id = u.id
      LEFT JOIN user_ad_stats    ar ON ar.user_id = u.id
      ORDER BY u.created_at DESC
    `, [start, end]);

    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 유저 상세 (주문/광고 집계) ───────────────────────────────────────────────
router.get('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const uid = parseInt(req.params.id, 10);

    const userQ = pool.query('SELECT * FROM users WHERE id = $1', [uid]);

    const ordersQ = pool.query(`
      SELECT
        DATE_TRUNC('month', TO_DATE(order_date, 'YYYY-MM-DD')) AS month,
        COUNT(*)::INTEGER                                       AS orders,
        SUM(payment_amount + shipping_fee)::BIGINT             AS revenue
      FROM orders
      WHERE user_id = $1 AND is_excluded = FALSE
        AND order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
      GROUP BY 1
      ORDER BY 1 DESC
      LIMIT 12
    `, [uid]);

    const adsQ = pool.query(`
      SELECT
        SUM(ad_cost)::NUMERIC(14,2)        AS total_ad_cost,
        SUM(actual_ad_cost)::NUMERIC(14,2) AS total_actual_ad_cost,
        SUM(clicks)::INTEGER               AS total_clicks,
        SUM(impressions)::INTEGER          AS total_impressions
      FROM ad_reports
      WHERE user_id = $1
    `, [uid]);

    const [userR, ordersR, adsR] = await Promise.all([userQ, ordersQ, adsQ]);

    if (!userR.rows[0]) return res.status(404).json({ error: 'User not found' });

    res.json({
      user:          userR.rows[0],
      monthly_stats: ordersR.rows,
      ad_stats:      adsR.rows[0],
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 유저 status 변경 ─────────────────────────────────────────────────────────
router.put('/admin/users/:id/status', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['pending', 'active', 'blocked'].includes(status)) {
      return res.status(400).json({ error: '유효하지 않은 status 값입니다.' });
    }
    const { rows } = await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2 RETURNING id, email, status',
      [status, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 승인 + 만료일 설정 ───────────────────────────────────────────────────────
router.put('/admin/users/:id/approve', requireAdmin, async (req, res) => {
  try {
    const expiresAt = req.body.expires_at || null; // null = 무제한
    const { rows } = await pool.query(
      `UPDATE users SET status = 'active', expires_at = $1
       WHERE id = $2 RETURNING id, email, status, expires_at`,
      [expiresAt, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 만료일만 변경 ────────────────────────────────────────────────────────────
router.put('/admin/users/:id/expires', requireAdmin, async (req, res) => {
  try {
    const expiresAt = req.body.expires_at || null;
    const { rows } = await pool.query(
      'UPDATE users SET expires_at = $1 WHERE id = $2 RETURNING id, email, status, expires_at',
      [expiresAt, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── 어드민 권한 부여/해제 ────────────────────────────────────────────────────
router.put('/admin/users/:id/admin', requireAdmin, async (req, res) => {
  try {
    const { is_admin } = req.body;
    const { rows } = await pool.query(
      'UPDATE users SET is_admin = $1 WHERE id = $2 RETURNING id, email, is_admin',
      [!!is_admin, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
