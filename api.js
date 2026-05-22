/**
 * api.js
 * B2B 사이트 등록, 최신 가격 조회, 수동 크롤링 트리거 REST API
 * + 사용자 인증 정보 및 개인 데이터 저장 API
 */

const express = require('express');
const router  = express.Router();
const { pool } = require('./db');

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

module.exports = router;
