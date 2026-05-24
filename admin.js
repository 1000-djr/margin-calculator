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

// ─── 전체 유저 목록 + 매출/순이익 집계 ───────────────────────────────────────
router.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        u.id,
        u.name,
        u.email,
        u.picture,
        u.status,
        u.is_admin,
        u.created_at,
        COALESCE(SUM(o.payment_amount + o.shipping_fee), 0)::BIGINT AS total_revenue,
        COUNT(DISTINCT o.id)::INTEGER                                AS total_orders
      FROM users u
      LEFT JOIN orders o ON o.user_id = u.id AND o.is_excluded = FALSE
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);
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
