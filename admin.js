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

// ─── 전체 유저 목록 + 수익분석 동일 수식 집계 ────────────────────────────────
// 쿼리 파라미터: start_date (YYYY-MM-DD), end_date (YYYY-MM-DD)
router.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const start = req.query.start_date || null;
    const end   = req.query.end_date   || null;

    const { rows } = await pool.query(`
      SELECT
        u.id,
        u.name,
        u.email,
        u.picture,
        u.status,
        u.is_admin,
        u.created_at,
        u.expires_at,
        COUNT(DISTINCT ord.id)::INTEGER                        AS total_orders,
        -- 실매출(쿠폰전) = 결제액 + 배송비
        COALESCE(SUM(ord.payment_amount + ord.shipping_fee), 0)::BIGINT
                                                               AS revenue_before,
        -- 실매출(쿠폰후) = 결제액 + 배송비 - 주문별 쿠폰할인
        COALESCE(SUM(ord.net_sale), 0)::BIGINT                 AS revenue_after,
        -- 수수료 = 실매출(쿠폰후) × 11.66%
        COALESCE(SUM(ord.net_sale * 0.1166), 0)::NUMERIC(14,2) AS commission,
        -- 실광고비 = 광고비 × 1.1 (already stored as actual_ad_cost)
        COALESCE(ar.actual_ad_cost, 0)::NUMERIC(14,2)          AS actual_ad_cost,
        -- 광고비(VAT 전, 부가세 계산용)
        COALESCE(ar.ad_cost_raw, 0)::NUMERIC(14,2)             AS ad_cost_raw
      FROM users u
      -- 미인식 주문 제외, 날짜 필터 적용한 주문에 쿠폰할인 계산
      LEFT JOIN (
        SELECT
          o.id, o.user_id, o.payment_amount, o.shipping_fee,
          GREATEST(
            o.payment_amount + o.shipping_fee
            - COALESCE((
                SELECT SUM(c.discount_amount)
                FROM coupons c
                WHERE c.user_id = o.user_id
                  AND c.option_ids @> jsonb_build_array(o.option_id)
                  AND (c.start_at IS NULL
                       OR SUBSTRING(o.order_date,1,10) >= TO_CHAR(c.start_at AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD'))
                  AND (c.end_at IS NULL
                       OR SUBSTRING(o.order_date,1,10) <= TO_CHAR(c.end_at AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD'))
              ), 0),
            0
          ) AS net_sale
        FROM orders o
        WHERE o.is_excluded = FALSE
          AND ($1::text IS NULL OR SUBSTRING(o.order_date,1,10) >= $1)
          AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) <= $2)
      ) ord ON ord.user_id = u.id
      -- 날짜 필터 적용한 광고비
      LEFT JOIN (
        SELECT
          user_id,
          SUM(actual_ad_cost)::NUMERIC(14,2) AS actual_ad_cost,
          SUM(ad_cost)::NUMERIC(14,2)        AS ad_cost_raw
        FROM ad_reports
        WHERE ($1::text IS NULL OR report_date >= $1)
          AND ($2::text IS NULL OR report_date <= $2)
        GROUP BY user_id
      ) ar ON ar.user_id = u.id
      GROUP BY u.id, ar.actual_ad_cost, ar.ad_cost_raw
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
