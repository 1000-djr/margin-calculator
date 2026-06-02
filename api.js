/**
 * api.js
 * B2B 사이트 등록, 최신 가격 조회, 수동 크롤링 트리거 REST API
 * + 사용자 인증 정보 및 개인 데이터 저장 API
 */

const express = require('express');
const router  = express.Router();
const { pool } = require('./db');
const { calculateProfit } = require('./profit');
const crypto = require('crypto');
const https  = require('https');
const zlib   = require('zlib');

// ─── AES-256-GCM 암호화 / 복호화 ─────────────────────────────────────────────
const AES_KEY = Buffer.from(
  (process.env.AES_SECRET_KEY || 'default-aes-key-32-bytes-padding!!').slice(0, 32).padEnd(32, '0'),
  'utf8'
);

function aesEncrypt(text) {
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted  = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag    = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted.toString('hex');
}

function aesDecrypt(stored) {
  const [ivHex, tagHex, encHex] = stored.split(':');
  const iv         = Buffer.from(ivHex, 'hex');
  const authTag    = Buffer.from(tagHex, 'hex');
  const encrypted  = Buffer.from(encHex, 'hex');
  const decipher   = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ─── 쿠팡 Open API HMAC-SHA256 인증 ──────────────────────────────────────────
function coupangDatetime() {
  const now = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${String(now.getUTCFullYear()).slice(-2)}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
}

function coupangAuth(method, urlPath, accessKey, secretKey) {
  const [path, qs = ''] = urlPath.split('?');
  const datetime  = coupangDatetime();
  const message   = datetime + method + path + qs;
  const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
  console.log(`[coupangAuth] datetime=${datetime} method=${method} path=${path} qs=${qs.slice(0, 80)}${qs.length > 80 ? '...' : ''}`);
  return {
    auth: `CEA algorithm=HmacSHA256, access-key=${accessKey}, signed-date=${datetime}, signature=${signature}`,
    path: urlPath,
  };
}

function coupangRequest(method, urlPath, accessKey, secretKey) {
  return new Promise((resolve, reject) => {
    const { auth, path } = coupangAuth(method, urlPath, accessKey, secretKey);
    const options = {
      hostname: 'api-gateway.coupang.com',
      port: 443,
      path,
      method,
      headers: {
        'Authorization': auth,
        'Content-Type': 'application/json;charset=UTF-8',
      },
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        const decode = (buf) => { try { return JSON.parse(buf.toString('utf-8')); } catch { return buf.toString('utf-8'); } };
        const enc = res.headers['content-encoding'];
        if (enc === 'gzip') {
          zlib.gunzip(raw, (err, decoded) => resolve({ status: res.statusCode, body: err ? raw.toString() : decode(decoded) }));
        } else {
          resolve({ status: res.statusCode, body: decode(raw) });
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── 서버사이드 마스킹 ────────────────────────────────────────────────────────
function maskName(name) {
  if (!name) return '';
  if (name.length <= 1) return name;
  if (name.length === 2) return name[0] + '*';
  return name[0] + '*'.repeat(name.length - 2) + name[name.length - 1];
}
function maskPhone(phone) {
  if (!phone) return '';
  return phone.replace(/(\d{3})-?(\d{3,4})-?(\d{4})/, (_, a, b, c) => `${a}-${'*'.repeat(b.length)}-${c}`);
}
function maskAddr(addr) {
  if (!addr) return '';
  const parts = addr.split(' ');
  if (parts.length <= 2) return addr;
  return parts.slice(0, 2).join(' ') + ' ***';
}

let crawlStatus = { running: false, lastRun: null, lastResult: null };

// ─── 인증 미들웨어 ────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: '로그인이 필요합니다.' });
  next();
}

// ─── 현재 유저 정보 ───────────────────────────────────────────────────────────
router.get('/auth/me', (req, res) => {
  if (!req.user) return res.json(null);
  const user = { ...req.user };
  if (req.originalAdmin) {
    user._impersonating    = true;
    user._originalAdmin    = { id: req.originalAdmin.id, name: req.originalAdmin.name, is_admin: req.originalAdmin.is_admin };
    user.is_admin          = false; // 대리접속 중에는 어드민 버튼 숨김 (어드민 페이지는 별도 링크로)
    user._originalIsAdmin  = true;
  }
  res.json(user);
});

// ─── 어드민 대리접속 ──────────────────────────────────────────────────────────
function requireRealAdmin(req, res, next) {
  const admin = req.originalAdmin || req.user;
  if (!admin)          return res.status(401).json({ error: '로그인이 필요합니다.' });
  if (!admin.is_admin) return res.status(403).json({ error: '어드민 권한이 필요합니다.' });
  next();
}

router.post('/admin/impersonate/exit', requireRealAdmin, (req, res) => {
  delete req.session.impersonating_user_id;
  res.json({ ok: true });
});

router.post('/admin/impersonate/:userId', requireRealAdmin, async (req, res) => {
  try {
    const adminUser = req.originalAdmin || req.user;
    const targetId  = parseInt(req.params.userId);
    if (targetId === adminUser.id) return res.status(400).json({ error: '자기 자신은 대리접속할 수 없습니다.' });

    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [targetId]);
    if (!rows.length) return res.status(404).json({ error: '유저 없음' });
    if (rows[0].is_admin) return res.status(400).json({ error: '어드민 계정은 대리접속할 수 없습니다.' });

    req.session.impersonating_user_id = targetId;
    res.json({ ok: true, user: rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 어드민 유저 진단 엔드포인트 ──────────────────────────────────────────────
// GET /api/admin/user-debug?email=xxx  또는  /api/admin/user-debug?user_id=N
router.get('/admin/user-debug', requireRealAdmin, async (req, res) => {
  try {
    const { email, user_id } = req.query;
    if (!email && !user_id) return res.status(400).json({ error: 'email 또는 user_id 파라미터 필요' });

    // 1. 유저 조회
    let userRow;
    if (email) {
      const { rows } = await pool.query('SELECT id, email, name, status, is_admin, expires_at, created_at FROM users WHERE email = $1', [email]);
      userRow = rows[0];
    } else {
      const { rows } = await pool.query('SELECT id, email, name, status, is_admin, expires_at, created_at FROM users WHERE id = $1', [parseInt(user_id)]);
      userRow = rows[0];
    }

    if (!userRow) return res.json({ found: false, message: '해당 유저 없음' });

    const uid = userRow.id;

    // 2. 주문 데이터 집계
    const { rows: orderStats } = await pool.query(`
      SELECT
        COUNT(*)::INTEGER                                           AS total_orders,
        COUNT(*) FILTER (WHERE is_excluded = false OR is_excluded IS NULL)::INTEGER AS active_orders,
        MIN(order_date)                                            AS oldest_order,
        MAX(order_date)                                            AS newest_order,
        MAX(created_at) AT TIME ZONE 'Asia/Seoul'                 AS last_uploaded_at
      FROM orders WHERE user_id = $1
    `, [uid]);

    // 3. 광고 데이터 집계
    const { rows: adStats } = await pool.query(`
      SELECT COUNT(*)::INTEGER AS total_ad_rows
      FROM ad_reports WHERE user_id = $1
    `, [uid]);

    // 4. 최근 주문 5건
    const { rows: recentOrders } = await pool.query(`
      SELECT id, order_number, order_date, product_name, payment_amount, is_excluded, exclusion_type, created_at
      FROM orders WHERE user_id = $1
      ORDER BY created_at DESC LIMIT 5
    `, [uid]);

    // 5. 원가 진단 쿼리
    const { rows: costDiag } = await pool.query(`
      SELECT
        (SELECT COUNT(*)::INTEGER FROM product_name_mapping WHERE user_id = $1) AS pnm_count,
        (SELECT COUNT(*)::INTEGER FROM b2b_products          WHERE user_id = $1) AS b2b_products_count,
        (SELECT COUNT(*)::INTEGER FROM b2b_prices            WHERE user_id = $1) AS b2b_prices_count,
        (SELECT COUNT(*)::INTEGER FROM orders
          WHERE user_id = $1 AND override_cost_price IS NOT NULL AND is_excluded = FALSE) AS override_orders_count,
        (SELECT COALESCE(SUM(override_cost_price * quantity), 0)::BIGINT FROM orders
          WHERE user_id = $1 AND override_cost_price IS NOT NULL AND is_excluded = FALSE) AS override_total_cost
    `, [uid]);

    // 6. override_cost_price 설정된 주문 샘플 (최대 10건)
    const { rows: overrideSamples } = await pool.query(`
      SELECT id, order_number, order_date, product_name, option_name,
             quantity, override_cost_price, override_cost_note
      FROM orders
      WHERE user_id = $1 AND override_cost_price IS NOT NULL AND is_excluded = FALSE
      ORDER BY override_cost_price * quantity DESC
      LIMIT 10
    `, [uid]);

    res.json({
      found: true,
      user: userRow,
      orders: {
        ...orderStats[0],
        recent: recentOrders,
      },
      ad_reports: adStats[0],
      cost_diagnosis: {
        ...costDiag[0],
        override_samples: overrideSamples,
        note: 'override_cost_price가 product_name_mapping보다 우선 적용됩니다. pnm_count=0이어도 override가 있으면 원가가 잡힙니다.',
      },
      note: 'raw_data는 별도 테이블이 아닌 ad_reports/returns 테이블의 JSONB 컬럼입니다.',
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/admin/cross-user-check?product_name=경북 부사 꿀사과
// 특정 상품명이 어느 계정에 있는지, 데이터가 섞였는지 진단
router.get('/admin/cross-user-check', requireRealAdmin, async (req, res) => {
  try {
    const { product_name, option_id } = req.query;
    if (!product_name && !option_id) return res.status(400).json({ error: 'product_name 또는 option_id 파라미터 필요' });

    const results = {};

    if (product_name) {
      const like = `%${product_name}%`;

      const { rows: orderRows } = await pool.query(`
        SELECT u.id AS user_id, u.email, u.name, COUNT(*) AS cnt,
               MIN(o.order_date) AS first_order, MAX(o.order_date) AS last_order
        FROM orders o JOIN users u ON u.id = o.user_id
        WHERE o.product_name ILIKE $1
        GROUP BY u.id, u.email, u.name
        ORDER BY cnt DESC
      `, [like]);
      results.orders_by_user = orderRows;

      const { rows: adRows } = await pool.query(`
        SELECT u.id AS user_id, u.email, u.name, COUNT(*) AS cnt,
               MIN(a.report_date) AS first_date, MAX(a.report_date) AS last_date
        FROM ad_reports a JOIN users u ON u.id = a.user_id
        WHERE a.product_name ILIKE $1
        GROUP BY u.id, u.email, u.name
        ORDER BY cnt DESC
      `, [like]);
      results.ad_reports_by_user = adRows;

      const { rows: pnmRows } = await pool.query(`
        SELECT u.id AS user_id, u.email, u.name, pnm.registered_name, pnm.option_id, pnm.b2b_name
        FROM product_name_mapping pnm JOIN users u ON u.id = pnm.user_id
        WHERE pnm.registered_name ILIKE $1 OR pnm.b2b_name ILIKE $1
      `, [like]);
      results.product_name_mapping_by_user = pnmRows;
    }

    if (option_id) {
      const { rows: ordOptRows } = await pool.query(`
        SELECT u.id AS user_id, u.email, u.name, COUNT(*) AS cnt,
               MAX(o.product_name) AS product_name, MAX(o.option_name) AS option_name
        FROM orders o JOIN users u ON u.id = o.user_id
        WHERE o.option_id = $1
        GROUP BY u.id, u.email, u.name
      `, [String(option_id)]);
      results.orders_option_by_user = ordOptRows;

      const { rows: adOptRows } = await pool.query(`
        SELECT u.id AS user_id, u.email, u.name, COUNT(*) AS cnt,
               MAX(a.product_name) AS product_name
        FROM ad_reports a JOIN users u ON u.id = a.user_id
        WHERE a.option_id = $1
        GROUP BY u.id, u.email, u.name
      `, [String(option_id)]);
      results.ad_reports_option_by_user = adOptRows;
    }

    res.json({ results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 어드민 전용: 특정 유저의 광고보고서 데이터 삭제 (오염 데이터 정리용)
router.delete('/admin/fix-ad-reports', requireRealAdmin, async (req, res) => {
  try {
    const { user_id, product_name, from_date, to_date } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id 필수' });

    let query = 'DELETE FROM ad_reports WHERE user_id = $1';
    const params = [parseInt(user_id)];
    let p = 2;

    if (product_name) {
      query += ` AND product_name ILIKE $${p++}`;
      params.push(`%${product_name}%`);
    }
    if (from_date) {
      query += ` AND report_date >= $${p++}`;
      params.push(from_date);
    }
    if (to_date) {
      query += ` AND report_date <= $${p++}`;
      params.push(to_date);
    }

    query += ' RETURNING id, user_id, report_date, product_name, option_id';
    const { rows } = await pool.query(query, params);
    console.log(`[admin/fix-ad-reports] 삭제 ${rows.length}건 by admin=${req.originalAdmin?.id || req.user.id}`);
    res.json({ deleted: rows.length, rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 유저 설정 ────────────────────────────────────────────────────────────────
router.get('/user-settings', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT discount_mode FROM users WHERE id=$1',
      [req.user.id]
    );
    res.json({ discount_mode: rows[0]?.discount_mode || 'coupon' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/user-settings', requireAuth, async (req, res) => {
  const { discount_mode } = req.body;
  if (!['coupon', 'fixed'].includes(discount_mode))
    return res.status(400).json({ error: 'discount_mode는 coupon 또는 fixed' });
  try {
    await pool.query(
      'UPDATE users SET discount_mode=$1 WHERE id=$2',
      [discount_mode, req.user.id]
    );
    res.json({ ok: true, discount_mode });
  } catch(e) { res.status(500).json({ error: e.message }); }
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

router.get('/orders/stats', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date, search } = req.query;

    // 사용자 할인 모드 조회
    const { rows: modeRows } = await pool.query('SELECT discount_mode FROM users WHERE id=$1', [req.user.id]);
    const discountMode = modeRows[0]?.discount_mode || 'coupon';

    const discountSubquery = discountMode === 'fixed'
      ? `SELECT fd.discount_amount
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
         ORDER BY fd.start_date DESC LIMIT 1`
      : `SELECT c.discount_amount
         FROM coupons c
         WHERE c.user_id = o.user_id
           AND c.option_ids @> jsonb_build_array(o.option_id)
           AND o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
           AND (c.start_at IS NULL
             OR SUBSTRING(o.order_date,1,10) >= TO_CHAR(c.start_at AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD'))
           AND (c.end_at IS NULL
             OR SUBSTRING(o.order_date,1,10) <= TO_CHAR(c.end_at AT TIME ZONE 'Asia/Seoul','YYYY-MM-DD'))
         ORDER BY c.discount_amount DESC, c.coupon_id DESC NULLS LAST LIMIT 1`;

    const params = [req.user.id];
    let where = 'o.user_id=$1';
    let p = 2;
    if (start_date) { where += ` AND SUBSTRING(o.order_date,1,10) >= $${p++}`; params.push(start_date); }
    if (end_date)   { where += ` AND SUBSTRING(o.order_date,1,10) <= $${p++}`; params.push(end_date); }
    if (search) {
      where += ` AND (o.product_name ILIKE $${p} OR o.display_name ILIKE $${p} OR o.option_name ILIKE $${p})`;
      params.push('%' + search + '%'); p++;
    }
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)::INTEGER                                                                         AS total_orders,
        COUNT(*) FILTER (WHERE o.is_excluded = false OR o.is_excluded IS NULL)::INTEGER          AS active_orders,
        COUNT(*) FILTER (WHERE o.is_excluded = true)::INTEGER                                    AS excluded_orders,
        COUNT(*) FILTER (WHERE o.exclusion_type = 'fake_order')::INTEGER                         AS fake_order_count,
        COUNT(*) FILTER (WHERE o.exclusion_type = 'return')::INTEGER                             AS return_count,
        COUNT(*) FILTER (WHERE o.exclusion_type = 'other')::INTEGER                              AS other_count,
        COUNT(*) FILTER (WHERE o.exclusion_type = 'cancel')::INTEGER                             AS cancel_count,
        COALESCE(SUM(o.payment_amount) FILTER (WHERE o.is_excluded = false OR o.is_excluded IS NULL), 0)::NUMERIC AS total_payment,
        COALESCE(SUM(o.shipping_fee)   FILTER (WHERE o.is_excluded = false OR o.is_excluded IS NULL), 0)::NUMERIC AS total_shipping,
        COALESCE(SUM(
          CASE WHEN (o.is_excluded = false OR o.is_excluded IS NULL)
          THEN GREATEST(o.payment_amount + COALESCE(o.shipping_fee,0) - COALESCE((${discountSubquery}), 0), 0)
          ELSE 0 END
        ), 0)::NUMERIC                                                                            AS coupon_applied_revenue,
        MIN(o.order_date)                                                                         AS oldest_order,
        MAX(o.order_date)                                                                         AS newest_order,
        MAX(o.created_at) AT TIME ZONE 'Asia/Seoul'                                              AS last_uploaded_at
      FROM orders o WHERE ${where}
    `, params);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/orders', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date, exclude_excluded, offset, limit, search, exclusion_filter, sort_col, sort_dir } = req.query;
    const usePagination = limit !== undefined;

    // WHERE 절 공통 빌더
    const params = [req.user.id];
    let where = 'user_id=$1';

    // 구버전 호환 (exclude_excluded=true)
    if (exclude_excluded === 'true') {
      where += ' AND (is_excluded IS NULL OR is_excluded = false)';
    }

    // 날짜 필터 — order_date는 VARCHAR, 'YYYY-MM-DD HH:mm' 또는 'YYYY.MM.DD' 혼용
    if (start_date) {
      params.push(start_date);
      where += ` AND REPLACE(LEFT(order_date, 10), '.', '-') >= $${params.length}`;
    }
    if (end_date) {
      params.push(end_date);
      where += ` AND REPLACE(LEFT(order_date, 10), '.', '-') <= $${params.length}`;
    }

    // 상품명 검색
    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      where += ` AND LOWER(product_name) LIKE $${params.length}`;
    }

    // 인식/미인식 필터
    if (exclusion_filter === 'included') {
      where += ' AND (is_excluded IS NULL OR is_excluded = false)';
    } else if (exclusion_filter === 'excluded') {
      where += ' AND is_excluded = true';
    } else if (['fake_order', 'return', 'other', 'cancel'].includes(exclusion_filter)) {
      params.push(exclusion_filter);
      where += ` AND exclusion_type = $${params.length}`;
    }

    // 정렬
    const sortColMap = { '주문일': 'order_date', '등록상품명': 'product_name' };
    const dbSortCol = sortColMap[sort_col] || 'order_date';
    const dbSortDir = sort_dir === 'asc' ? 'ASC' : 'DESC';

    // 데이터 쿼리 (공유 params 복사 후 LIMIT/OFFSET 추가)
    const dataParams = [...params];
    let q = `SELECT * FROM orders WHERE ${where} ORDER BY ${dbSortCol} ${dbSortDir}, created_at DESC`;
    if (usePagination) {
      const lim = Math.max(1, parseInt(limit) || 50);
      const off = Math.max(0, parseInt(offset) || 0);
      dataParams.push(lim); q += ` LIMIT $${dataParams.length}`;
      dataParams.push(off); q += ` OFFSET $${dataParams.length}`;
    }

    const countQ = `SELECT COUNT(*) FROM orders WHERE ${where}`;

    const [{ rows }, countResult] = await Promise.all([
      pool.query(q, dataParams),
      usePagination ? pool.query(countQ, params) : Promise.resolve({ rows: [{ count: null }] }),
    ]);
    console.log(`[GET /orders] user=${req.user.id} limit=${limit||'all'} offset=${offset||0} 결과=${rows.length}건`);

    const mapRow = r => ({
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
      'override_cost_price': r.override_cost_price != null ? parseFloat(r.override_cost_price) : null,
    });

    if (usePagination) {
      res.json({ orders: rows.map(mapRow), total: parseInt(countResult.rows[0].count) || 0 });
    } else {
      res.json(rows.map(mapRow));
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/orders/exclude-bulk', requireAuth, async (req, res) => {
  const { order_numbers, is_excluded, exclusion_type = 'normal' } = req.body;
  if (!Array.isArray(order_numbers) || !order_numbers.length)
    return res.status(400).json({ error: 'order_numbers 배열 필수' });
  if (order_numbers.length > 200)
    return res.status(400).json({ error: '한 번에 최대 200건까지 처리 가능합니다' });
  const VALID = ['normal','fake_order','return','other','cancel'];
  const safeType = VALID.includes(exclusion_type) ? exclusion_type : 'normal';
  try {
    // statement_timeout: 청크당 15초 (Railway 30초 HTTP timeout의 절반)
    const client = await pool.connect();
    let result;
    try {
      await client.query('SET LOCAL statement_timeout = 15000');
      result = await client.query(
        `UPDATE orders SET is_excluded=$1, exclusion_type=$2
         WHERE user_id=$3 AND order_number = ANY($4::varchar[])`,
        [is_excluded !== false, safeType, req.user.id, order_numbers]
      );
    } finally {
      client.release();
    }
    res.json({ updated: result.rowCount });
  } catch(e) {
    if (e.code === '57014') return res.status(504).json({ error: '처리 시간 초과, 다시 시도해주세요' });
    res.status(500).json({ error: e.message });
  }
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

  // 100건씩 멀티행 배치 INSERT (건별 쿼리 대비 ~100배 빠름)
  const BATCH = 100;
  const COLS  = 24; // INSERT 컬럼 수
  let inserted = 0;

  try {
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const placeholders = [];
      const params       = [];
      let p = 1;

      for (const o of batch) {
        placeholders.push(
          `($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7},$${p+8},$${p+9},$${p+10},$${p+11},$${p+12},$${p+13},$${p+14},$${p+15},$${p+16},$${p+17},$${p+18},$${p+19},$${p+20},$${p+21},$${p+22},$${p+23})`
        );
        params.push(
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
        );
        p += COLS;
      }

      const r = await pool.query(
        `INSERT INTO orders
         (user_id,order_number,bundle_number,order_date,product_name,option_name,
          display_name,display_product_id,option_id,payment_amount,shipping_fee,
          quantity,unit_price,courier,tracking_number,shipped_date,delivered_date,
          confirmed_date,payment_location,delivery_type,buyer_masked,
          recipient_name_masked,recipient_phone_masked,recipient_address_masked)
         VALUES ${placeholders.join(',')}
         ON CONFLICT (user_id, order_number) DO NOTHING`,
        params
      );
      inserted += r.rowCount;
      console.log(`[orders/bulk] 배치 ${start + 1}~${start + batch.length}: 삽입 ${r.rowCount}건`);
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

router.delete('/orders/by-period', requireAuth, async (req, res) => {
  const { start_date, end_date } = req.body || {};
  if (!start_date || !end_date) return res.status(400).json({ error: 'start_date, end_date 필수' });
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM orders
       WHERE user_id = $1
         AND REPLACE(LEFT(order_date, 10), '.', '-') BETWEEN $2 AND $3`,
      [req.user.id, start_date, end_date]
    );
    res.json({ ok: true, deleted: rowCount });
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
  console.log('[ad-reports/bulk] 업로드 요청 user_id=', userId, 'session_id=', req.sessionID, 'ip=', req.ip);
  if (!items.length) return res.json({ inserted: 0, skipped: 0, failed: 0, total: 0 });

  if (items[0]) {
    console.log(`[ad-reports/bulk] user=${userId} items=${items.length} 컬럼:`, Object.keys(items[0]).join(' | '));
  }

  // 배치 INSERT: 행별 쿼리 → 100건씩 멀티행 INSERT (처리속도 ~100배 향상)
  const COLS  = 47;
  const CHUNK = 100;
  let inserted = 0, skipped = 0, failed = 0;

  function buildRow(r) {
    const adCost      = safeFloat(r['광고비']) ?? 0;
    const adPlacement = r['광고 노출 지면'] !== undefined ? r['광고 노출 지면'] : null;
    return [
      userId,
      formatAdDate(r['날짜'] ?? ''),
      safeStr(r['캠페인 ID'] || r['캠페인ID']),
      safeStr(r['캠페인명']),
      safeStr(r['광고그룹']),
      safeStr(r['광고집행 상품명'] || r['광고집행상품명'] || ''),
      safeStr(r['광고집행 옵션ID'] || r['광고집행옵션ID'] || ''),
      safeStr(r['키워드']) ?? '',
      safeInt(r['노출수'])   ?? 0,
      safeInt(r['클릭수'])   ?? 0,
      adCost,
      Math.round(adCost * 1.1 * 100) / 100,
      safeInt(r['총 주문수(1일)'])        ?? safeInt(r['총주문수(1일)'])        ?? 0,
      safeInt(r['총 판매수량(1일)'])      ?? safeInt(r['총판매수량(1일)'])      ?? 0,
      safeFloat(r['총 전환매출액(1일)'])  ?? safeFloat(r['총전환매출액(1일)'])  ?? 0,
      safeInt(r['총 주문수(14일)'])       ?? safeInt(r['총주문수(14일)'])       ?? 0,
      safeInt(r['총 판매수량(14일)'])     ?? safeInt(r['총판매수량(14일)'])     ?? 0,
      safeFloat(r['총 전환매출액(14일)']) ?? safeFloat(r['총전환매출액(14일)']) ?? 0,
      JSON.stringify(r),
      safeStr(r['과금 방식'] || r['과금방식']),
      safeStr(r['판매방식']),
      safeStr(r['광고유형']),
      adPlacement,
      safeStr(r['클릭률']),
      safeStr(r['광고전환매출발생 상품명'] || r['광고전환매출발생상품명']),
      safeStr(r['광고전환매출발생 옵션ID'] || r['광고전환매출발생옵션ID']),
      safeInt(r['직접 주문수(1일)'])        ?? safeInt(r['직접주문수(1일)'])        ?? 0,
      safeInt(r['간접 주문수(1일)'])        ?? safeInt(r['간접주문수(1일)'])        ?? 0,
      safeInt(r['직접 판매수량(1일)'])      ?? safeInt(r['직접판매수량(1일)'])      ?? 0,
      safeInt(r['간접 판매수량(1일)'])      ?? safeInt(r['간접판매수량(1일)'])      ?? 0,
      safeFloat(r['직접 전환매출액(1일)'])  ?? safeFloat(r['직접전환매출액(1일)'])  ?? 0,
      safeFloat(r['간접 전환매출액(1일)'])  ?? safeFloat(r['간접전환매출액(1일)'])  ?? 0,
      safeInt(r['직접 주문수(14일)'])       ?? safeInt(r['직접주문수(14일)'])       ?? 0,
      safeInt(r['간접 주문수(14일)'])       ?? safeInt(r['간접주문수(14일)'])       ?? 0,
      safeInt(r['직접 판매수량(14일)'])     ?? safeInt(r['직접판매수량(14일)'])     ?? 0,
      safeInt(r['간접 판매수량(14일)'])     ?? safeInt(r['간접판매수량(14일)'])     ?? 0,
      safeFloat(r['직접 전환매출액(14일)']) ?? safeFloat(r['직접전환매출액(14일)']) ?? 0,
      safeFloat(r['간접 전환매출액(14일)']) ?? safeFloat(r['간접전환매출액(14일)']) ?? 0,
      safeStr(r['총광고수익률(1일)']),
      safeStr(r['직접광고수익률(1일)']),
      safeStr(r['간접광고수익률(1일)']),
      safeStr(r['총광고수익률(14일)']),
      safeStr(r['직접광고수익률(14일)']),
      safeStr(r['간접광고수익률(14일)']),
      safeStr(r['캠페인 시작일'] || r['캠페인시작일']),
      safeStr(r['캠페인 종료일'] || r['캠페인종료일']),
      safeStr(r['비고']),
    ];
  }

  const INSERT_SQL = `
    INSERT INTO ad_reports
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
    VALUES`;

  try {
    for (let start = 0; start < items.length; start += CHUNK) {
      const chunk = items.slice(start, start + CHUNK);
      const placeholders = [];
      const params       = [];
      let p = 1;

      for (const r of chunk) {
        const cols = Array.from({ length: COLS }, (_, i) => `$${p + i}`);
        placeholders.push(`(${cols.join(',')})`);
        params.push(...buildRow(r));
        p += COLS;
      }

      try {
        const result = await pool.query(
          INSERT_SQL + ' ' + placeholders.join(',') + ' ON CONFLICT DO NOTHING',
          params
        );
        inserted += result.rowCount;
        skipped  += chunk.length - result.rowCount;
      } catch (chunkErr) {
        // 배치 실패 시 행별로 폴백하여 에러 건수만 집계
        console.error(`[ad-reports/bulk] 청크 오류 — 행별 폴백 실행`, chunkErr.message);
        for (const r of chunk) {
          try {
            const result = await pool.query(
              INSERT_SQL + ' ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,' +
              '$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,' +
              '$39,$40,$41,$42,$43,$44,$45,$46,$47) ON CONFLICT DO NOTHING',
              buildRow(r)
            );
            if (result.rowCount > 0) inserted++;
            else skipped++;
          } catch (rowErr) {
            failed++;
            console.error(`[ad-reports/bulk] 행 저장 실패 user=${userId} 날짜=${r['날짜']}`, rowErr.message);
          }
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

router.delete('/ad-reports/by-period', requireAuth, async (req, res) => {
  const { start_date, end_date } = req.body || {};
  if (!start_date || !end_date) return res.status(400).json({ error: 'start_date, end_date 필수' });
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM ad_reports WHERE user_id=$1 AND report_date BETWEEN $2 AND $3`,
      [req.user.id, start_date, end_date]
    );
    res.json({ ok: true, deleted: rowCount });
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

// 쿠폰 대량 등록 (100건씩 배치 INSERT)
router.post('/coupons/bulk', requireAuth, async (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  if (!items.length) return res.json({ inserted: 0, skipped: 0, rows: [] });
  console.log(`[coupons/bulk] user=${req.user.id} items=${items.length}`);

  const BATCH = 100;
  let inserted = 0, skipped = 0;
  const insertedRows = [];

  try {
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const placeholders = [];
      const params       = [];
      let p = 1;

      for (const c of batch) {
        if (!c.name) { skipped++; continue; }
        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6})`);
        params.push(
          req.user.id,
          c.coupon_id       || null,
          c.name,
          c.discount_amount || 0,
          c.start_at        || null,
          c.end_at          || null,
          JSON.stringify(Array.isArray(c.option_ids) ? c.option_ids : []),
        );
        p += 7;
      }

      if (placeholders.length > 0) {
        const result = await pool.query(
          `INSERT INTO coupons (user_id,coupon_id,name,discount_amount,start_at,end_at,option_ids)
           VALUES ${placeholders.join(',')}
           ON CONFLICT (user_id, coupon_id) WHERE coupon_id IS NOT NULL DO NOTHING
           RETURNING *`,
          params
        );
        inserted += result.rowCount;
        result.rows.forEach(row => insertedRows.push(couponRow(row)));
        skipped  += (batch.filter(c => c.name).length - result.rowCount);
      }
    }
    res.json({ inserted, skipped, rows: insertedRows });
  } catch(e) {
    console.error('[coupons/bulk] DB 오류:', e.message);
    res.status(500).json({ error: e.message });
  }
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

router.delete('/coupons/all', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM coupons WHERE user_id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/coupons/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM coupons WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 상시할인가 ────────────────────────────────────────────────────────────────
function fdRow(r) {
  function toKSTDatetime(d) {
    if (!d) return null;
    // TIMESTAMPTZ → "YYYY-MM-DD HH:mm:ss" (KST)
    return d.toLocaleString('sv-SE', { timeZone: 'Asia/Seoul' }).replace('T', ' ');
  }
  return {
    id:              r.id,
    option_id:       r.option_id,
    product_name:    r.product_name || null,
    option_name:     r.option_name  || null,
    discount_amount: parseFloat(r.discount_amount) || 0,
    start_date:      toKSTDatetime(r.start_date) || '',
    end_date:        toKSTDatetime(r.end_date),
  };
}

// 옵션ID로 상품명/옵션명 조회: product_name_mapping 우선, 없으면 orders fallback
async function lookupOptionInfo(userId, optionId) {
  // 1순위: product_name_mapping (option_id 컬럼 기준)
  const { rows: pnm } = await pool.query(
    `SELECT registered_name AS product_name, option_name
     FROM product_name_mapping
     WHERE user_id = $1 AND option_id = $2
     LIMIT 1`,
    [userId, String(optionId)]
  );
  if (pnm.length && pnm[0].product_name) return pnm[0];

  // 2순위: orders (최신 주문 기준)
  const { rows: ord } = await pool.query(
    `SELECT product_name, option_name
     FROM orders
     WHERE user_id = $1 AND option_id = $2 AND product_name IS NOT NULL
     ORDER BY order_date DESC
     LIMIT 1`,
    [userId, String(optionId)]
  );
  return ord[0] || { product_name: null, option_name: null };
}

router.get('/fixed-discounts', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT fd.*,
              COALESCE(pnm.registered_name, o.product_name) AS product_name,
              COALESCE(pnm.option_name,     o.option_name)  AS option_name
       FROM fixed_discounts fd
       LEFT JOIN LATERAL (
         SELECT registered_name, option_name
         FROM product_name_mapping
         WHERE user_id = fd.user_id AND option_id = fd.option_id
         LIMIT 1
       ) pnm ON true
       LEFT JOIN LATERAL (
         SELECT product_name, option_name
         FROM orders
         WHERE user_id = fd.user_id
           AND option_id = fd.option_id
           AND product_name IS NOT NULL
         ORDER BY order_date DESC
         LIMIT 1
       ) o ON (pnm.registered_name IS NULL)
       WHERE fd.user_id = $1
       ORDER BY fd.start_date DESC, fd.created_at DESC`,
      [req.user.id]
    );
    res.json(rows.map(fdRow));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 옵션ID로 상품명/옵션명 미리보기
router.get('/fixed-discounts/option-info', requireAuth, async (req, res) => {
  const { option_id } = req.query;
  if (!option_id) return res.json({ product_name: null, option_name: null });
  try {
    const info = await lookupOptionInfo(req.user.id, option_id);
    res.json(info);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 동일 option_id 진행중 이력 전체 종료 (트랜잭션 client 사용)
async function autoCloseActiveDiscounts(client, userId, optionId, newStartDate) {
  const oid = String(optionId);
  const result = await client.query(
    `UPDATE fixed_discounts
     SET end_date = $3::TIMESTAMPTZ - INTERVAL '1 second'
     WHERE user_id = $1
       AND option_id = $2
       AND (end_date IS NULL OR end_date >= $3::TIMESTAMPTZ)`,
    [userId, oid, newStartDate]
  );
  console.log(`[autoClose] user=${userId} option_id=${oid} start=${newStartDate} → closed ${result.rowCount}건`);
  return result.rowCount;
}

router.post('/fixed-discounts', requireAuth, async (req, res) => {
  const { option_id, discount_amount, start_date, end_date } = req.body;
  if (!option_id)                               return res.status(400).json({ error: 'option_id 필수' });
  if (!discount_amount || discount_amount <= 0) return res.status(400).json({ error: '할인금액 필수' });
  if (!start_date)                              return res.status(400).json({ error: '시작일 필수' });
  const oid = String(option_id);
  console.log(`[fixed-discounts POST] user=${req.user.id} option_id=${oid} start_date=${start_date}`);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await autoCloseActiveDiscounts(client, req.user.id, oid, start_date);
    // ON CONFLICT DO UPDATE: start_date가 동일한 기존 레코드(DATE→TIMESTAMPTZ 마이그레이션 후 같은 UTC값)가
    // 있을 경우 INSERT 오류로 ROLLBACK되어 autoClose가 취소되는 버그 방지.
    // 충돌 시 기존 레코드를 새 값으로 갱신한다.
    const { rows } = await client.query(
      `INSERT INTO fixed_discounts (user_id,option_id,discount_amount,start_date,end_date)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (user_id,option_id,start_date)
       DO UPDATE SET discount_amount = EXCLUDED.discount_amount,
                     end_date        = EXCLUDED.end_date
       RETURNING *`,
      [req.user.id, oid, discount_amount, start_date, end_date || null]
    );
    await client.query('COMMIT');
    console.log(`[fixed-discounts POST] COMMIT → id=${rows[0]?.id}`);
    res.status(201).json(fdRow(rows[0]));
  } catch(e) {
    await client.query('ROLLBACK');
    console.error(`[fixed-discounts POST] ROLLBACK: ${e.message}`);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

router.post('/fixed-discounts/bulk', requireAuth, async (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  if (!items.length) return res.json({ inserted: 0, skipped: 0, errors: 0, rows: [] });
  const BATCH = 100;
  let inserted = 0, skipped = 0, errors = 0;
  const insertedRows = [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const validItems = [];
      for (const item of batch) {
        if (!item.option_id || !(item.discount_amount > 0) || !item.start_date) { errors++; continue; }
        validItems.push({ ...item, option_id: String(item.option_id) });
      }
      if (!validItems.length) continue;

      // 배치 내 고유 option_id별 자동 종료 처리
      const uniqueOids = [...new Set(validItems.map(it => it.option_id))];
      for (const oid of uniqueOids) {
        // 해당 option_id 중 가장 빠른 새 start_date 기준으로 종료
        const earliest = validItems
          .filter(it => it.option_id === oid)
          .map(it => it.start_date)
          .sort()[0];
        await autoCloseActiveDiscounts(client, req.user.id, oid, earliest);
      }

      const placeholders = [];
      const params = [];
      let p = 1;
      for (const item of validItems) {
        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4})`);
        params.push(req.user.id, item.option_id, item.discount_amount, item.start_date, item.end_date || null);
        p += 5;
      }
      const result = await client.query(
        `INSERT INTO fixed_discounts (user_id,option_id,discount_amount,start_date,end_date)
         VALUES ${placeholders.join(',')}
         ON CONFLICT (user_id,option_id,start_date) DO NOTHING
         RETURNING *`,
        params
      );
      inserted += result.rowCount;
      skipped  += placeholders.length - result.rowCount;
      result.rows.forEach(r => insertedRows.push(fdRow(r)));
    }
    await client.query('COMMIT');
    res.json({ inserted, skipped, errors, rows: insertedRows });
  } catch(e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

router.put('/fixed-discounts/:id', requireAuth, async (req, res) => {
  const { option_id, discount_amount, start_date, end_date } = req.body;
  if (!option_id)                          return res.status(400).json({ error: 'option_id 필수' });
  if (!discount_amount || discount_amount <= 0) return res.status(400).json({ error: '할인금액 필수' });
  if (!start_date)                         return res.status(400).json({ error: '시작일 필수' });
  try {
    const { rows } = await pool.query(
      `UPDATE fixed_discounts SET option_id=$3,discount_amount=$4,start_date=$5,end_date=$6
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id, option_id, discount_amount, start_date, end_date || null]
    );
    if (!rows.length) return res.status(404).json({ error: '항목을 찾을 수 없습니다' });
    res.json(fdRow(rows[0]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/fixed-discounts/:id/end', requireAuth, async (req, res) => {
  const { end_date } = req.body;
  if (!end_date) return res.status(400).json({ error: 'end_date 필수' });
  try {
    const { rows } = await pool.query(
      `UPDATE fixed_discounts SET end_date=$3 WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id, end_date]
    );
    if (!rows.length) return res.status(404).json({ error: '항목을 찾을 수 없습니다' });
    res.json(fdRow(rows[0]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/fixed-discounts/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM fixed_discounts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
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
  const { registered_name, option_name = '', b2b_name, b2b_unit = '', option_id = null } = req.body;
  if (!registered_name || !b2b_name) return res.status(400).json({ error: '필수값 누락' });
  const oid = option_id ? String(option_id) : null;
  try {
    let row;
    if (oid) {
      // option_id 기준 upsert: 기존 option_id 항목이 있으면 갱신, 없으면 이름 기준 insert/update
      const { rows: existing } = await pool.query(
        'SELECT id FROM product_name_mapping WHERE user_id=$1 AND option_id=$2',
        [req.user.id, oid]
      );
      if (existing.length) {
        const { rows } = await pool.query(
          `UPDATE product_name_mapping
             SET registered_name=$2, option_name=$3, b2b_name=$4, b2b_unit=$5
           WHERE user_id=$1 AND option_id=$6 RETURNING *`,
          [req.user.id, registered_name, option_name, b2b_name, b2b_unit, oid]
        );
        row = rows[0];
      } else {
        const { rows } = await pool.query(
          `INSERT INTO product_name_mapping
             (user_id, registered_name, option_name, b2b_name, b2b_unit, option_id)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (user_id, registered_name, option_name)
             DO UPDATE SET b2b_name=EXCLUDED.b2b_name, b2b_unit=EXCLUDED.b2b_unit,
                           option_id=EXCLUDED.option_id
           RETURNING *`,
          [req.user.id, registered_name, option_name, b2b_name, b2b_unit, oid]
        );
        row = rows[0];
      }
    } else {
      const { rows } = await pool.query(
        `INSERT INTO product_name_mapping (user_id, registered_name, option_name, b2b_name, b2b_unit)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (user_id, registered_name, option_name)
           DO UPDATE SET b2b_name=EXCLUDED.b2b_name, b2b_unit=EXCLUDED.b2b_unit
         RETURNING *`,
        [req.user.id, registered_name, option_name, b2b_name, b2b_unit]
      );
      row = rows[0];
    }
    res.json(row);
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

  console.log('[returns/bulk] 수신:', items.length, '건');

  const BATCH = 100;
  let inserted = 0, skipped = 0;

  try {
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const placeholders = [];
      const params       = [];
      let p = 1;

      for (const r of batch) {
        const raw  = r.raw_data || {};
        const productName = raw['노출상품명'] || raw['상품명'] || r.product_name || null;
        const optionName  = raw['옵션']       || raw['옵션명'] || r.option_name  || null;
        const orderNumber = raw['주문번호']   || r.order_number || null;

        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7},$${p+8},$${p+9},$${p+10},$${p+11},$${p+12},$${p+13},$${p+14},$${p+15},$${p+16},$${p+17},$${p+18},$${p+19},$${p+20},$${p+21},$${p+22},$${p+23},$${p+24},$${p+25})`);
        params.push(
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
        );
        p += 26;
      }

      const result = await pool.query(`
        INSERT INTO returns (
          user_id, received_at, receipt_number, delivery_status, return_status,
          warehousing_status, warehousing_method, warehousing_tracking,
          product_name, option_name, quantity, return_reason,
          return_shipping_fee, shipping_fee_burden, refund_amount,
          recipient_masked, phone_masked, return_address_masked, collection_address_masked,
          order_number, expected_ship_date, warehousing_complete_date,
          return_complete_date, receipt_channel, option_id, raw_data
        ) VALUES ${placeholders.join(',')}
        ON CONFLICT (user_id, receipt_number) DO NOTHING
      `, params);
      inserted += result.rowCount;
      skipped  += batch.length - result.rowCount;
      console.log(`[returns/bulk] 배치 ${start + 1}~${start + batch.length}: 삽입 ${result.rowCount}건`);
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

  const BATCH = 100;

  try {
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const placeholders = [];
      const params       = [];
      let p = 1;

      for (const r of items.slice(start, start + BATCH)) {
        const orderNumber = r.order_number || null;
        if (orderNumber) cancelOrderNumbers.push(orderNumber);
        if (!r.receipt_number) continue; // 접수번호 없는 건은 returns INSERT 제외

        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7},$${p+8},$${p+9},$${p+10},$${p+11},$${p+12},$${p+13},$${p+14},'cancel',$${p+15})`);
        params.push(
          req.user.id,
          r.received_at         || null,
          r.receipt_number,
          r.delivery_status     || null,
          r.product_name        || null,
          r.option_name         || null,
          parseInt(r.quantity)  || 1,
          r.return_reason       || null,
          r.recipient_masked    || null,
          r.phone_masked        || null,
          orderNumber,
          r.expected_ship_date  || null,
          r.stop_complete_date  || null,
          r.receipt_channel     || null,
          r.option_id           || null,
          r.raw_data ? JSON.stringify(r.raw_data) : null,
        );
        p += 16;
      }

      if (placeholders.length > 0) {
        const result = await pool.query(`
          INSERT INTO returns (
            user_id, received_at, receipt_number, delivery_status,
            product_name, option_name, quantity, return_reason,
            recipient_masked, phone_masked,
            order_number, expected_ship_date, warehousing_complete_date,
            receipt_channel, option_id, record_type, raw_data
          ) VALUES ${placeholders.join(',')}
          ON CONFLICT (user_id, receipt_number) DO NOTHING
        `, params);
        inserted += result.rowCount;
        skipped  += placeholders.length - result.rowCount;
        console.log(`[cancel-shipments/bulk] 배치 ${start + 1}~${start + batch.length}: 삽입 ${result.rowCount}건`);
      }
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

// ─── 쿠팡 반품/출고중지 API 동기화 ────────────────────────────────────────────

// 쿠팡 returnRequests API 페이지네이션 수집 헬퍼
async function fetchReturnRequests(vendorId, accessKey, secretKey, from, to, status) {
  const allItems = [];
  let nextToken  = null;
  let pageIndex  = 1;
  let callCount  = 0;
  const MAX_CALLS = 200;

  do {
    let qs;
    if (nextToken) {
      qs = `searchType=timeFrame&createdAtFrom=${encodeURIComponent(from)}&createdAtTo=${encodeURIComponent(to)}&status=${status}&maxPerPage=50&nextToken=${encodeURIComponent(nextToken)}`;
    } else {
      qs = `searchType=timeFrame&createdAtFrom=${encodeURIComponent(from)}&createdAtTo=${encodeURIComponent(to)}&status=${status}&maxPerPage=50&pageIndex=${pageIndex}`;
    }

    const urlPath = `/v2/providers/openapi/apis/api/v6/vendors/${vendorId}/returnRequests?${qs}`;
    console.log(`[return-sync] status=${status} call#${callCount + 1}: GET ${urlPath}`);

    const result = await coupangRequest('GET', urlPath, accessKey, secretKey);
    callCount++;

    console.log(`[return-sync] response status=${result.status} body=${JSON.stringify(result.body).slice(0, 200)}`);

    if (result.status !== 200) {
      const err = new Error(`쿠팡 API 오류 HTTP ${result.status}`);
      err.httpStatus = result.status;
      err.body       = result.body;
      throw err;
    }

    const body  = result.body || {};
    const items = Array.isArray(body.data) ? body.data : [];
    allItems.push(...items);

    nextToken = body.nextToken || null;
    pageIndex++;

    if (!nextToken && items.length < 50) break;
  } while (callCount < MAX_CALLS);

  return allItems;
}

// API 키 + secretKey 복호화 공통 헬퍼
async function getCoupangKeys(userId) {
  const { rows } = await pool.query(
    'SELECT vendor_id, access_key, secret_key FROM coupang_api_keys WHERE user_id=$1 AND is_active=TRUE',
    [userId]
  );
  if (!rows[0]) throw Object.assign(new Error('쿠팡 API 키가 등록되지 않았습니다.'), { noKey: true });
  const { vendor_id, access_key, secret_key: encSecret } = rows[0];
  let secretKey;
  try { secretKey = aesDecrypt(encSecret); } catch(e) {
    throw Object.assign(new Error('API 키 복호화 실패. 키를 다시 저장해 주세요.'), { decryptErr: true });
  }
  return { vendor_id, access_key, secretKey };
}

// 마지막 동기화 시간 조회
router.get('/returns/sync-status', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT returns_last_sync_at, cancel_last_sync_at FROM users WHERE id=$1',
      [req.user.id]
    );
    const u = rows[0] || {};
    res.json({
      returns_last_sync_at: u.returns_last_sync_at || null,
      cancel_last_sync_at:  u.cancel_last_sync_at  || null,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 반품(UC) API 동기화
router.post('/returns/sync', requireAuth, async (req, res) => {
  const { from, to } = req.body;
  if (!from || !to) return res.status(400).json({ error: 'from, to 필수 (YYYY-MM-DDTHH:mm)' });
  try {
    const { vendor_id, access_key, secretKey } = await getCoupangKeys(req.user.id);
    const allItems = await fetchReturnRequests(vendor_id, access_key, secretKey, from, to, 'UC');
    console.log(`[returns/sync] UC 수신: ${allItems.length}건`);
    if (allItems.length > 0) {
      console.log('[returns/sync] ★ 첫 번째 항목 전체 필드:', JSON.stringify(allItems[0], null, 2));
    }

    let inserted = 0, skipped = 0;
    const orderNumbers = [];
    const BATCH = 100;

    for (let start = 0; start < allItems.length; start += BATCH) {
      const batch = allItems.slice(start, start + BATCH);
      const placeholders = [];
      const params = [];
      let p = 1;

      for (const item of batch) {
        const receiptNum = item.receiptId ? String(item.receiptId) : null;
        if (!receiptNum) { skipped++; continue; }
        const orderNum = item.orderId ? String(item.orderId) : null;
        if (orderNum) orderNumbers.push(orderNum);

        const ri = Array.isArray(item.returnItems) && item.returnItems[0] ? item.returnItems[0] : {};
        const returnType = item.faultByType === 'VENDOR' ? 'seller'
                         : item.faultByType === 'BUYER'  ? 'buyer'
                         : 'other';

        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7},$${p+8},$${p+9},$${p+10},'return',$${p+11},$${p+12},$${p+13})`);
        params.push(
          req.user.id,                                              // user_id
          receiptNum,                                               // receipt_number
          item.createdAt                             || null,       // received_at (접수일)
          orderNum,                                                 // order_number
          ri.vendorItemPackageName                   || null,       // product_name (노출상품명)
          ri.vendorItemName || ri.sellerProductName  || null,       // option_name (옵션명)
          parseInt(ri.cancelCount)                   || 1,          // quantity (수량)
          parseInt(item.returnShippingCharge?.units) || 0,          // return_shipping_fee (반품배송비)
          parseInt(item.enclosePrice?.units)         || 0,          // refund_amount (환불예정금액)
          item.reasonCodeText                        || null,       // return_reason (취소사유)
          item.status                                || null,       // delivery_status
          JSON.stringify(item),                                     // raw_data
          ri.vendorItemId ? String(ri.vendorItemId)  : null,       // option_id (옵션ID)
          returnType,                                               // return_type (반품유형)
        );
        p += 14;
      }

      if (!placeholders.length) continue;
      const result = await pool.query(`
        INSERT INTO returns (
          user_id, receipt_number, received_at, order_number,
          product_name, option_name, quantity,
          return_shipping_fee, refund_amount, return_reason,
          delivery_status, record_type, raw_data,
          option_id, return_type
        ) VALUES ${placeholders.join(',')}
        ON CONFLICT (user_id, receipt_number) DO NOTHING
      `, params);
      inserted += result.rowCount;
      skipped  += batch.length - result.rowCount;
    }

    let ordersUpdated = 0;
    if (orderNumbers.length) {
      const { rowCount } = await pool.query(
        `UPDATE orders SET is_excluded=TRUE, exclusion_type='return' WHERE user_id=$1 AND order_number=ANY($2)`,
        [req.user.id, orderNumbers]
      );
      ordersUpdated = rowCount;
    }

    const syncedAt = new Date();
    await pool.query('UPDATE users SET returns_last_sync_at=$2 WHERE id=$1', [req.user.id, syncedAt]);

    res.json({ inserted, skipped, ordersUpdated, synced_at: syncedAt.toISOString(), total_fetched: allItems.length });
  } catch(e) {
    if (e.noKey || e.decryptErr) return res.status(400).json({ error: e.message });
    if (e.httpStatus) return res.status(502).json({ error: e.message, detail: e.body });
    res.status(500).json({ error: e.message });
  }
});

// 출고중지(RU) API 동기화
router.post('/cancel-shipments/sync', requireAuth, async (req, res) => {
  const { from, to } = req.body;
  if (!from || !to) return res.status(400).json({ error: 'from, to 필수 (YYYY-MM-DDTHH:mm)' });
  try {
    const { vendor_id, access_key, secretKey } = await getCoupangKeys(req.user.id);
    const allItems = await fetchReturnRequests(vendor_id, access_key, secretKey, from, to, 'RU');
    console.log(`[cancel/sync] RU 수신: ${allItems.length}건`);

    let inserted = 0, skipped = 0;
    const orderNumbers = [];
    const BATCH = 100;

    for (let start = 0; start < allItems.length; start += BATCH) {
      const batch = allItems.slice(start, start + BATCH);
      const placeholders = [];
      const params = [];
      let p = 1;

      for (const item of batch) {
        const receiptNum = item.receiptId ? String(item.receiptId) : null;
        if (!receiptNum) { skipped++; continue; }
        const orderNum = item.orderId ? String(item.orderId) : null;
        if (orderNum) orderNumbers.push(orderNum);

        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7},$${p+8},$${p+9},$${p+10},'cancel',$${p+11})`);
        params.push(
          req.user.id,
          receiptNum,
          item.receivedAt                          || null,
          orderNum,
          item.productName || item.exposedProductName || null,
          item.optionName                          || null,
          parseInt(item.quantity)                  || 1,
          parseInt(item.returnShippingCharge)      || 0,
          parseInt(item.refundAmount)              || 0,
          item.returnReason                        || null,
          item.status                              || null,
          JSON.stringify(item),
        );
        p += 12;
      }

      if (!placeholders.length) continue;
      const result = await pool.query(`
        INSERT INTO returns (
          user_id, receipt_number, received_at, order_number,
          product_name, option_name, quantity,
          return_shipping_fee, refund_amount, return_reason,
          delivery_status, record_type, raw_data
        ) VALUES ${placeholders.join(',')}
        ON CONFLICT (user_id, receipt_number) DO NOTHING
      `, params);
      inserted += result.rowCount;
      skipped  += batch.length - result.rowCount;
    }

    let ordersUpdated = 0;
    if (orderNumbers.length) {
      const { rowCount } = await pool.query(
        `UPDATE orders SET is_excluded=TRUE, exclusion_type='cancel' WHERE user_id=$1 AND order_number=ANY($2)`,
        [req.user.id, orderNumbers]
      );
      ordersUpdated = rowCount;
    }

    const syncedAt = new Date();
    await pool.query('UPDATE users SET cancel_last_sync_at=$2 WHERE id=$1', [req.user.id, syncedAt]);

    res.json({ inserted, skipped, ordersUpdated, synced_at: syncedAt.toISOString(), total_fetched: allItems.length });
  } catch(e) {
    if (e.noKey || e.decryptErr) return res.status(400).json({ error: e.message });
    if (e.httpStatus) return res.status(502).json({ error: e.message, detail: e.body });
    res.status(500).json({ error: e.message });
  }
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
  const { ids, restore_order } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids 배열 필수' });
  const intIds = ids.map(Number).filter(n => n > 0);
  if (!intIds.length) return res.status(400).json({ error: '유효한 id가 없습니다.' });
  console.log(`[DELETE /returns] user=${req.user.id} ids=${intIds} restore_order=${restore_order}`);
  try {
    // 삭제 전 주문번호 수집
    let orderNumbers = [];
    if (restore_order) {
      const { rows } = await pool.query(
        `SELECT DISTINCT order_number FROM returns
          WHERE user_id=$1 AND id = ANY($2::int[]) AND order_number IS NOT NULL`,
        [req.user.id, intIds]
      );
      orderNumbers = rows.map(r => r.order_number);
    }

    const { rowCount } = await pool.query(
      'DELETE FROM returns WHERE user_id=$1 AND id = ANY($2::int[])',
      [req.user.id, intIds]
    );
    console.log(`[DELETE /returns] deleted=${rowCount}`);

    let ordersRestored = 0;
    if (restore_order && orderNumbers.length) {
      const { rowCount: rc } = await pool.query(
        `UPDATE orders
            SET is_excluded = FALSE, exclusion_type = NULL
          WHERE user_id = $1
            AND order_number = ANY($2)
            AND exclusion_type IN ('return', 'cancel')`,
        [req.user.id, orderNumbers]
      );
      ordersRestored = rc;
      console.log(`[DELETE /returns] ordersRestored=${ordersRestored}`);
    }

    res.json({ deleted: rowCount, ordersRestored });
  } catch(e) {
    console.error('[DELETE /returns] error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

router.delete('/returns/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id || id <= 0) return res.status(400).json({ error: '유효하지 않은 id' });
  const { restore_order } = req.body || {};
  console.log(`[DELETE /returns/:id] user=${req.user.id} id=${id} restore_order=${restore_order}`);
  try {
    // 삭제 전 주문번호 조회
    const { rows } = await pool.query(
      'SELECT order_number FROM returns WHERE id=$1 AND user_id=$2',
      [id, req.user.id]
    );
    if (!rows.length) {
      console.log(`[DELETE /returns/:id] 404 not found id=${id} user=${req.user.id}`);
      return res.status(404).json({ error: '반품 없음' });
    }
    const orderNumber = rows[0].order_number;

    await pool.query(
      'DELETE FROM returns WHERE id=$1 AND user_id=$2',
      [id, req.user.id]
    );
    console.log(`[DELETE /returns/:id] deleted id=${id} orderNumber=${orderNumber}`);

    let orderRestored = false;
    if (restore_order && orderNumber) {
      const { rowCount } = await pool.query(`
        UPDATE orders
           SET is_excluded    = FALSE,
               exclusion_type = NULL
         WHERE user_id = $1
           AND order_number = $2
           AND exclusion_type IN ('return', 'cancel')
      `, [req.user.id, orderNumber]);
      orderRestored = rowCount > 0;
    }

    res.json({ deleted: 1, orderNumber, orderRestored });
  } catch(e) {
    console.error('[DELETE /returns/:id] error:', e.message);
    res.status(500).json({ error: e.message });
  }
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
    const { rows: modeRows } = await pool.query(
      'SELECT discount_mode FROM users WHERE id=$1',
      [req.user.id]
    );
    const discountMode = modeRows[0]?.discount_mode || 'coupon';
    const result = await calculateProfit(
      req.user.id,
      start_date || null,
      end_date   || null,
      group_by,
      discountMode
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
    const { vendor_name, method, review_type, delivery_fee, process_fee,
            process_fee_vat_type, delivery_fee_vat_type, product_cost } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO fake_purchase_vendors
         (user_id, vendor_name, method, review_type, delivery_fee, process_fee,
          process_fee_vat_type, delivery_fee_vat_type, product_cost)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.id, vendor_name, method || '빈박스', review_type || '별점',
       delivery_fee || 0, process_fee || 0,
       process_fee_vat_type || '별도', delivery_fee_vat_type || '별도', product_cost || 0]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.put('/fake-vendors/:id', requireAuth, async (req, res) => {
  try {
    const { vendor_name, method, review_type, delivery_fee, process_fee,
            process_fee_vat_type, delivery_fee_vat_type, product_cost } = req.body;
    const { rows } = await pool.query(
      `UPDATE fake_purchase_vendors
         SET vendor_name=$1, method=$2, review_type=$3,
             delivery_fee=$4, process_fee=$5,
             process_fee_vat_type=$6, delivery_fee_vat_type=$7, product_cost=$8
       WHERE id=$9 AND user_id=$10 RETURNING *`,
      [vendor_name, method, review_type, delivery_fee, process_fee,
       process_fee_vat_type || '별도', delivery_fee_vat_type || '별도', product_cost,
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
      `SELECT o.id, o.order_number, o.product_name, o.option_name, o.quantity,
              o.payment_amount, o.shipping_fee,
              o.payment_amount + o.shipping_fee AS net_sale,
              GREATEST(
                o.payment_amount + o.shipping_fee
                - COALESCE((
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
                    LIMIT 1
                  ), 0),
                0
              ) AS net_sale_after_coupon,
              o.exclusion_type,
              EXISTS (
                SELECT 1 FROM fake_purchase_records r
                WHERE r.user_id = o.user_id
                  AND r.order_ids @> jsonb_build_array(o.id)
              ) AS already_recorded
         FROM orders o
        WHERE o.user_id = $1
          AND ($2::text IS NULL OR SUBSTRING(o.order_date,1,10) = $2)
          AND o.exclusion_type = 'fake_order'
          AND o.is_excluded = TRUE
        ORDER BY o.id DESC`,
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
              v.delivery_fee, v.process_fee, v.process_fee_vat_type, v.product_cost
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
    const { vendor_id, proceed_date, order_ids, total_cost, tax_type } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO fake_purchase_records (user_id, vendor_id, proceed_date, order_ids, total_cost, tax_type)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.user.id, vendor_id, proceed_date, JSON.stringify(order_ids || []), total_cost || 0, tax_type || '면세']
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

// ─── 가구매 기록 상세 (주문별 내역) ─────────────────────────────────────────
router.get('/fake-records/:id/detail', requireAuth, async (req, res) => {
  try {
    // 기록 + 업체 정보 조회
    const { rows: recRows } = await pool.query(
      `SELECT r.*, v.vendor_name, v.method, v.review_type,
              v.delivery_fee, v.delivery_fee_vat_type,
              v.process_fee, v.process_fee_vat_type, v.product_cost
         FROM fake_purchase_records r
         JOIN fake_purchase_vendors v ON v.id = r.vendor_id
        WHERE r.id = $1 AND r.user_id = $2`,
      [req.params.id, req.user.id]
    );
    if (!recRows.length) return res.status(404).json({ error: '없음' });
    const rec = recRows[0];

    // order_ids로 주문 상세 조회 (쿠폰 적용 매출 포함)
    const orderIds = rec.order_ids || [];
    let orders = [];
    if (orderIds.length > 0) {
      const { rows: oRows } = await pool.query(
        `SELECT o.id, o.order_number, o.product_name, o.option_name, o.quantity,
                o.payment_amount, o.shipping_fee,
                o.payment_amount + o.shipping_fee AS net_sale,
                GREATEST(
                  o.payment_amount + o.shipping_fee
                  - COALESCE((
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
                      LIMIT 1
                    ), 0),
                  0
                ) AS net_sale_after_coupon
           FROM orders o
          WHERE o.id = ANY($1::int[]) AND o.user_id = $2
          ORDER BY o.id`,
        [orderIds, req.user.id]
      );
      orders = oRows;
    }

    res.json({ record: rec, orders });
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

// ─── 쿠팡 Open API 키 관리 ────────────────────────────────────────────────────

// 연결 상태 확인
router.get('/coupang-keys/status', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, vendor_id, access_key, is_active, updated_at FROM coupang_api_keys WHERE user_id = $1',
      [req.user.id]
    );
    if (!rows[0]) return res.json({ connected: false });
    res.json({
      connected:  rows[0].is_active,
      vendor_id:  rows[0].vendor_id,
      access_key: rows[0].access_key,
      updated_at: rows[0].updated_at,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 연결 테스트 (입력값으로 직접 테스트)
router.post('/coupang-keys/test', requireAuth, async (req, res) => {
  try {
    const { vendor_id, access_key, secret_key } = req.body;
    if (!vendor_id || !access_key || !secret_key)
      return res.status(400).json({ error: 'vendor_id, access_key, secret_key 모두 필요합니다.' });

    const today   = new Date().toISOString().slice(0, 10);
    const urlPath = `/v2/providers/openapi/apis/api/v4/vendors/${vendor_id}/ordersheets?createdAtFrom=${today}&createdAtTo=${today}&status=ACCEPT&maxPerPage=1&pageIndex=1`;
    const result  = await coupangRequest('GET', urlPath, access_key, secret_key);

    console.log(`[test] vendor=${vendor_id} status=${result.status} body_preview=${JSON.stringify(result.body).slice(0, 200)}`);

    if (result.status === 200) {
      const body = result.body;
      console.log(`[test] data_type=${Array.isArray(body?.data) ? 'array' : typeof body?.data} nextToken_location=${body?.nextToken ? 'root' : body?.data?.nextToken ? 'data' : 'none'}`);
      res.json({ ok: true, message: '연결 성공' });
    } else {
      res.json({ ok: false, message: `HTTP ${result.status}: ${typeof result.body === 'string' ? result.body : JSON.stringify(result.body)}` });
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DB에 저장된 키로 직접 진단 (HMAC 메시지 + API 호출 결과 전체 반환)
router.get('/coupang-keys/debug', requireAuth, async (req, res) => {
  // is_admin 또는 본인 계정만 허용
  const targetUserId = req.user.is_admin && req.query.user_id
    ? parseInt(req.query.user_id)
    : req.user.id;
  if (!req.user.is_admin && targetUserId !== req.user.id)
    return res.status(403).json({ error: '권한 없음' });

  try {
    // 1. DB 키 조회
    const { rows } = await pool.query(
      'SELECT vendor_id, access_key, secret_key FROM coupang_api_keys WHERE user_id = $1',
      [targetUserId]
    );

    if (!rows[0]) {
      return res.json({
        db:     { found: false },
        hmac:   null,
        coupang: null,
      });
    }

    const dbRow = rows[0];

    // 2. 복호화
    let secretKey, decryptError;
    try {
      secretKey = aesDecrypt(dbRow.secret_key);
    } catch (e) {
      decryptError = e.message;
    }

    const dbInfo = {
      found:             true,
      vendor_id:         dbRow.vendor_id,
      access_key:        dbRow.access_key.slice(0, 8) + '...',
      decrypt_error:     decryptError || null,
      secret_key_prefix: secretKey ? secretKey.slice(0, 6) + '...' : null,
      secret_key_suffix: secretKey ? '...' + secretKey.slice(-4)   : null,
    };

    if (decryptError) return res.json({ db: dbInfo, hmac: null, coupang: null });

    // 3. HMAC 생성
    const today   = new Date().toISOString().slice(0, 10);
    const urlPath = `/v2/providers/openapi/apis/api/v4/vendors/${dbRow.vendor_id}/ordersheets?createdAtFrom=${today}&createdAtTo=${today}&status=ACCEPT&maxPerPage=1&pageIndex=1`;
    const [pathPart, qsPart = ''] = urlPath.split('?');
    const datetime  = coupangDatetime();
    const hmacMsg   = datetime + 'GET' + pathPart + qsPart;
    const signature = crypto.createHmac('sha256', secretKey).update(hmacMsg).digest('hex');

    // 4. 실제 API 호출
    const result = await coupangRequest('GET', urlPath, dbRow.access_key, secretKey);
    const bodyStr = typeof result.body === 'string'
      ? result.body.slice(0, 300)
      : JSON.stringify(result.body).slice(0, 300);

    res.json({
      db: dbInfo,
      hmac: {
        message:   hmacMsg,
        datetime,
        path:      pathPart,
        signature: signature.slice(0, 20) + '...',
      },
      coupang: {
        status: result.status,
        body:   bodyStr,
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 키 저장
router.post('/coupang-keys', requireAuth, async (req, res) => {
  try {
    const { vendor_id, access_key, secret_key } = req.body;
    if (!vendor_id || !access_key || !secret_key)
      return res.status(400).json({ error: 'vendor_id, access_key, secret_key 모두 필요합니다.' });

    const encryptedSecret = aesEncrypt(secret_key);

    await pool.query(
      `INSERT INTO coupang_api_keys (user_id, vendor_id, access_key, secret_key, is_active, updated_at)
       VALUES ($1, $2, $3, $4, TRUE, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET vendor_id = $2, access_key = $3, secret_key = $4, is_active = TRUE, updated_at = NOW()`,
      [req.user.id, vendor_id, access_key, encryptedSecret]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 쿠팡 주문 동기화 ─────────────────────────────────────────────────────────
router.post('/orders/sync', requireAuth, async (req, res) => {
  try {
    const { start_date, end_date } = req.body;
    if (!start_date || !end_date)
      return res.status(400).json({ error: 'start_date, end_date 필요합니다. (YYYY-MM-DD)' });

    // API 키 조회
    const { rows: keyRows } = await pool.query(
      'SELECT vendor_id, access_key, secret_key FROM coupang_api_keys WHERE user_id = $1 AND is_active = TRUE',
      [req.user.id]
    );
    if (!keyRows[0]) return res.status(400).json({ error: '쿠팡 API 키가 등록되지 않았습니다.' });

    const { vendor_id, access_key, secret_key: encSecret } = keyRows[0];
    let secretKey;
    try {
      secretKey = aesDecrypt(encSecret);
    } catch (decErr) {
      console.error('[sync] AES 복호화 실패:', decErr.message);
      return res.status(500).json({ error: 'API 키 복호화 실패. 키를 다시 저장해 주세요.' });
    }

    console.log(`[sync] user=${req.user.id} vendor=${vendor_id} access_key=${access_key.slice(0, 8)}... secret_len=${secretKey.length}`);

    // nextToken 루프로 모든 페이지 수집
    // ※ Coupang ordersheets 응답 구조:
    //   { code, message, data: [ {orderId, orderItems, ...}, ... ], nextToken: "..." }
    //   → data.data 가 배열, data.nextToken 이 커서 (data.data.orderSheets/nextToken 아님)
    // ※ nextToken 사용 시 pageIndex 를 함께 보내면 403 → 둘 중 하나만 사용
    const allItems = [];
    let nextToken  = null;
    let pageIndex  = 1;
    let callCount  = 0;

    do {
      let qs;
      if (nextToken) {
        // 2페이지 이후: nextToken 만 사용, pageIndex 제외
        qs = `createdAtFrom=${start_date}&createdAtTo=${end_date}&status=ACCEPT&maxPerPage=50&nextToken=${encodeURIComponent(nextToken)}`;
      } else {
        // 첫 페이지: pageIndex=1
        qs = `createdAtFrom=${start_date}&createdAtTo=${end_date}&status=ACCEPT&maxPerPage=50&pageIndex=${pageIndex}`;
      }

      const urlPath = `/v2/providers/openapi/apis/api/v4/vendors/${vendor_id}/ordersheets?${qs}`;
      console.log(`[sync] call #${callCount + 1}: GET ${urlPath}`);

      const result = await coupangRequest('GET', urlPath, access_key, secretKey);
      callCount++;

      console.log(`[sync] response status=${result.status} body_preview=${JSON.stringify(result.body).slice(0, 200)}`);

      if (result.status !== 200) {
        return res.status(502).json({
          error:  `쿠팡 API 오류 HTTP ${result.status}`,
          detail: result.body,
          url:    urlPath.replace(secretKey, '***'), // secret_key 가 url에 없지만 안전하게
        });
      }

      const body = result.body;
      // data 필드가 배열인 경우(정상) vs 객체인 경우 모두 대응
      const rawData = body?.data;
      const items   = Array.isArray(rawData) ? rawData : (rawData?.orderSheets || rawData?.content || []);
      allItems.push(...items);

      // nextToken 은 루트 레벨에 있음 (data.nextToken 아님)
      nextToken = body?.nextToken || body?.data?.nextToken || null;
      pageIndex++;
    } while (nextToken && callCount < 100);

    // 주문 항목 매핑 + DB upsert
    let inserted = 0;
    let skipped  = 0;

    // 첫 번째 item 전체 구조 로깅 (필드명 확인용)
    const firstSheet = allItems[0];
    const firstItem  = firstSheet?.orderItems?.[0];
    if (firstItem) {
      console.log('[sync] sheet keys:', Object.keys(firstSheet).join(', '));
      console.log('[sync] item keys:', Object.keys(firstItem).join(', '));
      console.log('[sync] item sample:', JSON.stringify(firstItem).slice(0, 500));
    }

    for (const sheet of allItems) {
      for (const item of (sheet.orderItems || [])) {
        const orderNumber = String(sheet.orderId || '');
        if (!orderNumber) { skipped++; continue; }

        // 날짜+시간 포맷: orderedAt은 ISO 문자열 (KST 기준)
        // "2026-05-28T10:30:15" → "2026-05-28 10:30:15"
        const rawOrderedAt = sheet.orderedAt || '';
        const orderDate = rawOrderedAt.length >= 19
          ? rawOrderedAt.slice(0, 19).replace('T', ' ')
          : rawOrderedAt.length >= 16
            ? rawOrderedAt.slice(0, 16).replace('T', ' ')
            : rawOrderedAt.slice(0, 10);

        const productName = item.sellerProductName || '';
        const optionName  = item.sellerProductItemName || '';

        // 옵션ID: sellerProductItemId (셀러 등록 옵션ID = Wing 엑셀의 "옵션ID")
        // null/undefined 안전하게 처리 (0도 유효한 값이므로 || 대신 != null 사용)
        const optionId = item.sellerProductItemId != null
          ? String(item.sellerProductItemId)
          : (item.vendorItemId != null ? String(item.vendorItemId) : '');

        // 노출상품ID: vendorItemId (쿠팡 노출 기준 ID = Wing 엑셀의 "노출상품ID")
        const displayProductId = item.vendorItemId != null
          ? String(item.vendorItemId)
          : (item.externalVendorSkuCode != null ? String(item.externalVendorSkuCode) : '');

        // 노출상품명(옵션명): vendorItemName → 없으면 sellerProductItemName
        const displayName = item.vendorItemName || item.sellerProductItemName || '';

        const paymentAmt   = Math.round(Number(item.orderPrice || 0));
        const shippingFee  = Math.round(Number(sheet.shippingPrice || 0));
        const qty          = Number(item.quantity || 1);
        const unitPrice    = qty > 0 ? Math.round(paymentAmt / qty) : paymentAmt;
        const bundleNumber = String(sheet.shipmentBoxId || '');

        const buyerMasked     = maskName(sheet.orderer?.name || '');
        const recipientMasked = maskName(sheet.receiver?.name || '');
        const phoneMasked     = maskPhone(sheet.receiver?.safeNumber || sheet.receiver?.phone || '');
        const addrMasked      = maskAddr(sheet.receiver?.addr1 || '');

        try {
          const upsertRes = await pool.query(
            `INSERT INTO orders (
              user_id, order_number, bundle_number, order_date,
              product_name, option_name, display_name, display_product_id, option_id,
              payment_amount, shipping_fee, quantity, unit_price,
              buyer_masked, recipient_name_masked, recipient_phone_masked, recipient_address_masked,
              is_excluded, exclusion_type
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,FALSE,'normal')
            ON CONFLICT (user_id, order_number) DO UPDATE SET
              display_product_id = CASE
                WHEN orders.display_product_id IS NULL OR orders.display_product_id = ''
                THEN EXCLUDED.display_product_id ELSE orders.display_product_id END,
              option_id = CASE
                WHEN orders.option_id IS NULL OR orders.option_id = ''
                THEN EXCLUDED.option_id ELSE orders.option_id END,
              display_name = CASE
                WHEN orders.display_name IS NULL OR orders.display_name = ''
                THEN EXCLUDED.display_name ELSE orders.display_name END
            RETURNING id, (xmax = 0) AS is_insert`,
            [
              req.user.id, orderNumber, bundleNumber, orderDate,
              productName, optionName, displayName, displayProductId, optionId,
              paymentAmt, shippingFee, qty, unitPrice,
              buyerMasked, recipientMasked, phoneMasked, addrMasked,
            ]
          );
          if (upsertRes.rowCount > 0 && upsertRes.rows[0]?.is_insert) inserted++;
          else skipped++;
        } catch (dbErr) {
          console.error('[sync] DB insert error:', dbErr.message);
          skipped++;
        }
      }
    }

    // ── 공급가 크로스체크 ─────────────────────────────────────────────────────
    // 동기화된 주문 대상으로 원가 매칭 여부 및 공급가 변동 여부 체크 (비블로킹)
    const seenOptions = new Map();
    for (const sheet of allItems) {
      for (const item of (sheet.orderItems || [])) {
        const oid   = item.sellerProductItemId != null ? String(item.sellerProductItemId) : '';
        const pname = item.sellerProductName || '';
        const oname = item.sellerProductItemName || '';
        const rawAt = sheet.orderedAt || '';
        const odate = rawAt.length >= 10 ? rawAt.slice(0, 10) : '';
        if (!odate) continue;
        const key = oid || `${pname}||${oname}`;
        if (!seenOptions.has(key)) {
          seenOptions.set(key, { option_id: oid || null, product_name: pname, option_name: oname, order_date: odate });
        }
      }
    }

    let no_match_count = 0, cost_changed_count = 0;
    const cost_changed_detail = [];

    try {
      for (const ci of seenOptions.values()) {
        const { rows: cc } = await pool.query(`
          SELECT
            bp.cost::NUMERIC AS current_cost,
            (
              SELECT bp2.cost::NUMERIC
              FROM b2b_prices bp2
              WHERE bp2.user_id        = bp.user_id
                AND bp2.b2b_product_id = bp.b2b_product_id
                AND bp.start_date IS NOT NULL
                AND bp2.start_date < bp.start_date
              ORDER BY bp2.start_date DESC
              LIMIT 1
            ) AS prev_cost
          FROM product_name_mapping pnm
          JOIN b2b_products b2bp
            ON b2bp.user_id = pnm.user_id
           AND b2bp.name    = pnm.b2b_name
           AND b2bp.unit    = pnm.b2b_unit
          JOIN b2b_prices bp
            ON bp.user_id        = pnm.user_id
           AND bp.b2b_product_id = b2bp.id
           AND (bp.start_date IS NULL OR bp.start_date <= $3::date)
           AND (bp.end_date   IS NULL OR bp.end_date   >= $3::date)
          WHERE pnm.user_id = $1
            AND (
              ($2 IS NOT NULL AND pnm.option_id IS NOT NULL AND pnm.option_id = $2)
              OR (pnm.option_id IS NULL AND pnm.registered_name = $4
                  AND pnm.option_name = COALESCE($5, ''))
            )
          ORDER BY (pnm.option_id IS NOT NULL) DESC, bp.start_date DESC NULLS LAST
          LIMIT 1
        `, [req.user.id, ci.option_id, ci.order_date, ci.product_name, ci.option_name]);

        if (!cc.length) {
          no_match_count++;
        } else {
          const cur = parseFloat(cc[0].current_cost);
          const prv = cc[0].prev_cost !== null ? parseFloat(cc[0].prev_cost) : null;
          if (prv !== null && cur !== prv) {
            cost_changed_count++;
            cost_changed_detail.push({
              product_name:  ci.product_name,
              option_name:   ci.option_name,
              prev_cost:     Math.round(prv),
              current_cost:  Math.round(cur),
            });
          }
        }
      }
    } catch (ccErr) {
      console.error('[sync] 크로스체크 오류:', ccErr.message);
    }

    // 마지막 동기화 시간 저장
    const now = new Date();
    await pool.query(
      'UPDATE users SET last_sync_at = $1 WHERE id = $2',
      [now, req.user.id]
    );

    res.json({
      ok: true,
      total_fetched: allItems.length,
      inserted,
      skipped,
      last_sync_at: now.toISOString(),
      cross_check: { no_match: no_match_count, cost_changed: cost_changed_count, cost_changed_detail },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 마지막 동기화 시간 조회 ────────────────────────────────────────────────────
router.get('/orders/last-sync', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT last_sync_at FROM users WHERE id = $1',
      [req.user.id]
    );
    res.json({ last_sync_at: rows[0]?.last_sync_at || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 도매처 관리 ──────────────────────────────────────────────────────────────
router.get('/wholesale-suppliers', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM wholesale_suppliers WHERE user_id=$1 ORDER BY created_at ASC',
      [req.user.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/wholesale-suppliers', requireAuth, async (req, res) => {
  const { name, url } = req.body;
  if (!name || !url) return res.status(400).json({ error: '이름과 URL을 입력하세요' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO wholesale_suppliers (user_id,name,url) VALUES ($1,$2,$3) RETURNING *',
      [req.user.id, name.trim(), url.trim()]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.put('/wholesale-suppliers/:id', requireAuth, async (req, res) => {
  const { name, url } = req.body;
  if (!name || !url) return res.status(400).json({ error: '이름과 URL을 입력하세요' });
  try {
    const { rows } = await pool.query(
      'UPDATE wholesale_suppliers SET name=$1, url=$2 WHERE id=$3 AND user_id=$4 RETURNING *',
      [name.trim(), url.trim(), req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: '항목 없음' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/wholesale-suppliers/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM wholesale_suppliers WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── 트래픽 슬롯 ──────────────────────────────────────────────────────────────

function trafficSlotRow(r) {
  return {
    id:            r.id,
    vendor_name:   r.vendor_name,
    option_id:     r.option_id,
    product_name:  r.product_name  || null,
    option_name:   r.option_name   || null,
    slot_count:    parseInt(r.slot_count)      || 0,
    cost_per_slot: parseFloat(r.cost_per_slot) || 0,
    vat_included:  r.vat_included === true || r.vat_included === 't',
    start_date:    r.start_date ? r.start_date.toISOString() : null,
    end_date:      r.end_date   ? r.end_date.toISOString()   : null,
    created_at:    r.created_at ? r.created_at.toISOString() : null,
  };
}

router.get('/traffic-slots', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ts.*,
        (SELECT o.product_name FROM orders o
          WHERE o.user_id = ts.user_id AND o.option_id = ts.option_id
            AND o.product_name IS NOT NULL AND o.product_name <> ''
          ORDER BY o.created_at DESC LIMIT 1) AS product_name,
        (SELECT o.option_name FROM orders o
          WHERE o.user_id = ts.user_id AND o.option_id = ts.option_id
            AND o.option_name IS NOT NULL AND o.option_name <> ''
          ORDER BY o.created_at DESC LIMIT 1) AS option_name
      FROM traffic_slots ts
      WHERE ts.user_id = $1
      ORDER BY ts.created_at DESC
    `, [req.user.id]);
    res.json(rows.map(trafficSlotRow));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/traffic-slots/bulk', requireAuth, async (req, res) => {
  const items = Array.isArray(req.body) ? req.body : [];
  if (!items.length) return res.json({ inserted: 0, skipped: 0 });
  let inserted = 0, skipped = 0;
  for (const item of items) {
    if (!item.vendor_name || !item.option_id) { skipped++; continue; }
    try {
      await pool.query(`
        INSERT INTO traffic_slots
          (user_id, vendor_name, option_id, slot_count, cost_per_slot, vat_included, start_date, end_date)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      `, [req.user.id, item.vendor_name, item.option_id,
          item.slot_count || 1, item.cost_per_slot || 0,
          !!item.vat_included, item.start_date, item.end_date]);
      inserted++;
    } catch(e) { skipped++; }
  }
  res.json({ inserted, skipped });
});

router.post('/traffic-slots', requireAuth, async (req, res) => {
  const { vendor_name, option_id, slot_count, cost_per_slot, vat_included, start_date, end_date } = req.body;
  if (!vendor_name) return res.status(400).json({ error: 'vendor_name 필수' });
  if (!option_id)   return res.status(400).json({ error: 'option_id 필수' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO traffic_slots
        (user_id, vendor_name, option_id, slot_count, cost_per_slot, vat_included, start_date, end_date)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *
    `, [req.user.id, vendor_name, option_id,
        slot_count || 1, cost_per_slot || 0, !!vat_included, start_date, end_date]);
    const slot = rows[0];
    const { rows: nameRows } = await pool.query(
      `SELECT product_name, option_name FROM orders
        WHERE user_id=$1 AND option_id=$2
          AND product_name IS NOT NULL AND product_name <> ''
        ORDER BY created_at DESC LIMIT 1`,
      [req.user.id, option_id]
    );
    slot.product_name = nameRows[0]?.product_name || null;
    slot.option_name  = nameRows[0]?.option_name  || null;
    res.status(201).json(trafficSlotRow(slot));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.put('/traffic-slots/:id', requireAuth, async (req, res) => {
  const { vendor_name, option_id, slot_count, cost_per_slot, vat_included, start_date, end_date } = req.body;
  if (!vendor_name) return res.status(400).json({ error: 'vendor_name 필수' });
  if (!option_id)   return res.status(400).json({ error: 'option_id 필수' });
  try {
    const { rows } = await pool.query(`
      UPDATE traffic_slots
        SET vendor_name=$3, option_id=$4, slot_count=$5,
            cost_per_slot=$6, vat_included=$7, start_date=$8, end_date=$9
      WHERE id=$1 AND user_id=$2 RETURNING *
    `, [req.params.id, req.user.id, vendor_name, option_id,
        slot_count || 1, cost_per_slot || 0, !!vat_included, start_date, end_date]);
    if (!rows.length) return res.status(404).json({ error: '없음' });
    const slot = rows[0];
    const { rows: nameRows } = await pool.query(
      `SELECT product_name, option_name FROM orders
        WHERE user_id=$1 AND option_id=$2
          AND product_name IS NOT NULL AND product_name <> ''
        ORDER BY created_at DESC LIMIT 1`,
      [req.user.id, option_id]
    );
    slot.product_name = nameRows[0]?.product_name || null;
    slot.option_name  = nameRows[0]?.option_name  || null;
    res.json(trafficSlotRow(slot));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/traffic-slots/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM traffic_slots WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
