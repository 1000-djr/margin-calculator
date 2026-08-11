/**
 * api.js
 * B2B 사이트 등록, 최신 가격 조회, 수동 크롤링 트리거 REST API
 * + 사용자 인증 정보 및 개인 데이터 저장 API
 */

const express = require('express');
const router  = express.Router();
const { pool } = require('./db');
const { calculateProfit } = require('./profit');
const { ORDER_FORMS } = require('./orderForms');
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

// ─── 도매처 API 시크릿 암호화 (ENCRYPTION_KEY 전용) ──────────────────────────
function encryptSecret(plain) {
  const keyRaw = process.env.ENCRYPTION_KEY;
  if (!keyRaw) throw new Error('ENCRYPTION_KEY 환경변수가 설정되지 않았습니다. Railway 환경변수에 32바이트 이상의 키를 설정해주세요.');
  const key = Buffer.from(keyRaw.slice(0, 32).padEnd(32, '0'), 'utf8');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString('base64') + ':' + tag.toString('base64') + ':' + encrypted.toString('base64');
}

function decryptSecret(enc) {
  const keyRaw = process.env.ENCRYPTION_KEY;
  if (!keyRaw) throw new Error('ENCRYPTION_KEY 환경변수 미설정');
  const key = Buffer.from(keyRaw.slice(0, 32).padEnd(32, '0'), 'utf8');
  const [ivB64, tagB64, encB64] = enc.split(':');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const encrypted = Buffer.from(encB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ─── 어드민플러스 API 헬퍼 ─────────────────────────────────────────────────────
async function adminplusGetToken(clientId, clientSecret) {
  const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret });
  const r = await fetch('https://api.adminplus.co.kr/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString()
  });
  const j = await r.json();
  if (!j.success) throw new Error('토큰 발급 실패: ' + j.message);
  return j.data.access_token;
}

async function adminplusGetProducts(token, params = {}) {
  const url = new URL('https://api.adminplus.co.kr/v1/seller/products');
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const r = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } });
  const j = await r.json();
  if (!j.success) throw new Error('상품 조회 실패: ' + j.message);
  return j.data;
}

async function adminplusGetBalance(token) {
  const r = await fetch('https://api.adminplus.co.kr/v1/seller/balance', {
    headers: { 'Authorization': 'Bearer ' + token }
  });
  const j = await r.json();
  return { http: r.status, success: j.success, message: j.message, data: j.data };
}

async function adminplusGetOrders(token, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = 'https://api.adminplus.co.kr/v1/seller/orders' + (qs ? '?' + qs : '');
  const r = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' } });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { status: r.status, data };
}

// 전화번호 정규화: 숫자만 추출
function normalizePhone(p) { return p ? String(p).replace(/\D/g, '') : ''; }

// 도매처 송장 전체 수집 (커서 페이지네이션, 발송완료 건만)
async function fetchSupplierInvoices(userId, supplierId) {
  const { rows } = await pool.query(
    `SELECT * FROM wholesale_suppliers WHERE id=$1 AND user_id=$2 AND api_linked=true AND api_type='adminplus'`,
    [supplierId, userId]
  );
  if (!rows.length) throw new Error(`도매처 API 설정 없음 (supplier_id=${supplierId})`);
  const cfg = getSupplierApiConfig(rows[0]);
  if (!cfg) throw new Error('도매처 API 설정 파싱 실패');
  const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);

  const invoices = [];
  let cursor = null;
  let page = 0;
  const MAX_PAGES = 50;

  while (page < MAX_PAGES) {
    const params = { limit: '100' };
    if (cursor) params.cursor = cursor;
    const result = await adminplusGetOrders(token, params);
    if (result.status !== 200 || !result.data?.success) break;

    const orders = result.data?.data?.orders || result.data?.orders || [];
    for (const order of orders) {
      const products = order.order_producs || order.order_products || [];
      for (const p of products) {
        if (!p.tracking_number) continue;
        invoices.push({
          customer_order_code: order.customer_order_code || '',
          receiver_phone: normalizePhone(order.receiver_hp || order.receiver_phone || ''),
          receiver_name: order.receiver_name || '',
          receiver_address: order.receiver_address || '',
          product_name: p.product_name || '',
          shipping_company: p.shipping_company || '',
          tracking_number: p.tracking_number,
        });
      }
    }

    const hasMore = result.data?.data?.has_more ?? result.data?.has_more ?? false;
    cursor = result.data?.data?.next_cursor ?? result.data?.next_cursor ?? null;
    if (!hasMore || !cursor) break;
    page++;
  }
  return invoices;
}

// ─── 도매처 잔액 조회+저장 (스케줄러/수동 공용) ────────────────────────────────
async function fetchSupplierBalancesForUser(userId) {
  const { rows: suppliers } = await pool.query(
    `SELECT * FROM wholesale_suppliers WHERE user_id=$1 AND api_linked=true AND api_type='adminplus' ORDER BY id`,
    [userId]
  );
  const out = [];
  for (const s of suppliers) {
    try {
      const cfg = getSupplierApiConfig(s);
      const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);
      const bal = await adminplusGetBalance(token);
      if (bal.success) {
        const dep = bal.data?.deposit_balance ?? 0;
        const pt = bal.data?.point_balance ?? 0;
        await pool.query(
          `INSERT INTO supplier_balances (user_id,supplier_id,deposit_balance,point_balance,fetched_at)
           VALUES ($1,$2,$3,$4,NOW())
           ON CONFLICT (user_id,supplier_id) DO UPDATE SET
             deposit_balance=EXCLUDED.deposit_balance, point_balance=EXCLUDED.point_balance, fetched_at=NOW()`,
          [userId, s.id, dep, pt]
        );
        out.push({ supplier: s.name, ok: true, deposit: dep, point: pt });
      } else {
        out.push({ supplier: s.name, ok: false, error: bal.message });
      }
    } catch(e) {
      out.push({ supplier: s.name, ok: false, error: String(e.message) });
    }
  }
  return out;
}

// ─── 도매처 API 설정 추출 헬퍼 ────────────────────────────────────────────────
function getSupplierApiConfig(supplier) {
  if (!supplier.api_linked || !supplier.api_type) return null;
  if (supplier.api_type === 'adminplus') {
    const clientSecret = supplier.api_client_secret_enc ? decryptSecret(supplier.api_client_secret_enc) : null;
    return { type: 'adminplus', clientId: supplier.api_client_id, clientSecret };
  }
  return null;
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
router.get('/auth/me', async (req, res) => {
  if (!req.user) return res.json(null);

  // 멤버 전용 계정 자동 진입:
  // 세션에 impersonating_user_id가 없고 _noAutoSwitch 플래그도 없으면
  // 멤버 전용 계정인지 확인하여 자동으로 첫 번째 공유 계정으로 전환
  if (!req.session.impersonating_user_id && !req.session._noAutoSwitch && !req.originalAdmin) {
    try {
      const loginUserId = req.user.id;
      if (await isMemberOnlyAccount(loginUserId)) {
        const { rows: ownerRows } = await pool.query(
          `SELECT s.owner_user_id, u.*
             FROM account_shares s
             JOIN users u ON u.id = s.owner_user_id
            WHERE s.member_user_id = $1 AND s.status = 'active'
            LIMIT 1`,
          [loginUserId]
        );
        if (ownerRows.length) {
          req.session.impersonating_user_id = ownerRows[0].owner_user_id;
          req.originalUser   = req.user;
          req.isSharedAccess = true;
          req.user           = ownerRows[0];
        }
      }
    } catch (e) {
      console.warn('[auth/me] 자동 전환 오류:', e.message);
    }
  }

  const user = { ...req.user };
  if (req.originalAdmin) {
    user._impersonating    = true;
    user._originalAdmin    = { id: req.originalAdmin.id, name: req.originalAdmin.name, is_admin: req.originalAdmin.is_admin };
    user.is_admin          = false; // 대리접속 중에는 어드민 버튼 숨김 (어드민 페이지는 별도 링크로)
    user._originalIsAdmin  = true;
  }
  if (req.isSharedAccess) {
    user._actingAs  = { id: req.user.id, name: req.user.name, email: req.user.email };
    user._isShared  = true;
    user.is_admin   = false; // 공유 멤버는 어드민 권한 없음
  }
  // 멤버 전용 계정 여부 (전환 중이 아닐 때만 의미 있음)
  if (!req.isSharedAccess && !req.originalAdmin) {
    try {
      user._memberOnly = await isMemberOnlyAccount(req.user.id);
    } catch (e) { user._memberOnly = false; }
  }
  res.json(user);
});

// ─── 어드민 대리접속 ──────────────────────────────────────────────────────────
function requireRealAdmin(req, res, next) {
  // 실제 로그인한 유저 기준으로 판정 (공유 멤버가 owner의 is_admin을 상속하는 구멍 방지)
  const realUser = req.originalUser || req.user;
  if (!realUser)          return res.status(401).json({ error: '로그인이 필요합니다.' });
  if (!realUser.is_admin) return res.status(403).json({ error: '어드민 권한이 필요합니다.' });
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

// ─── 멤버 전용 계정 판정 헬퍼 ────────────────────────────────────────────────
// '본인 데이터 0건 + 공유받은 계정 1개 이상' 이면 true
async function isMemberOnlyAccount(userId) {
  const { rows: shared } = await pool.query(
    `SELECT 1 FROM account_shares WHERE member_user_id = $1 AND status = 'active' LIMIT 1`,
    [userId]
  );
  if (!shared.length) return false;
  const { rows: own } = await pool.query(
    `SELECT
       (SELECT COUNT(*) FROM orders     WHERE user_id = $1) +
       (SELECT COUNT(*) FROM ad_reports WHERE user_id = $1) +
       (SELECT COUNT(*) FROM b2b_prices WHERE user_id = $1) AS cnt`,
    [userId]
  );
  return (parseInt(own[0]?.cnt) || 0) === 0;
}

// ─── 계정 공유 (팀 기능) 엔드포인트 ─────────────────────────────────────────

// GET /api/shares/accessible — 내가 접근 가능한 계정 목록 (본인 + 공유받은 owner들)
// 멤버 전용 계정이면 본인(is_self) 항목을 제외하고 공유받은 계정만 반환
router.get('/shares/accessible', requireAuth, async (req, res) => {
  try {
    const realUser = req.originalUser || req.user;
    const results  = [];

    // 공유받은 owner 계정들
    const { rows: sharedRows } = await pool.query(
      `SELECT u.id, u.name, u.email
         FROM account_shares s
         JOIN users u ON u.id = s.owner_user_id
        WHERE s.member_user_id = $1 AND s.status = 'active'`,
      [realUser.id]
    );
    sharedRows.forEach(r => results.push({ ...r, is_self: false }));

    // 본인 계정 — 멤버 전용 계정이면 숨김 (공유받은 계정이 없으면 잠기지 않도록 항상 포함)
    const memberOnly = sharedRows.length > 0 && await isMemberOnlyAccount(realUser.id);
    if (!memberOnly) {
      const { rows: selfRows } = await pool.query(
        'SELECT id, name, email FROM users WHERE id = $1', [realUser.id]
      );
      if (selfRows.length) results.unshift({ ...selfRows[0], is_self: true });
    }

    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/shares/switch/:userId — 그 계정으로 전환
router.post('/shares/switch/:userId', requireAuth, async (req, res) => {
  try {
    const realUser = req.originalUser || req.user;
    const targetId = parseInt(req.params.userId);

    if (targetId === realUser.id) {
      // 자기 자신으로 전환 = 전환 해제
      delete req.session.impersonating_user_id;
      return res.json({ ok: true });
    }

    // 어드민이거나 공유 권한 있으면 허용
    let allowed = realUser.is_admin;
    if (!allowed) {
      const { rows } = await pool.query(
        `SELECT id FROM account_shares
          WHERE owner_user_id = $1 AND member_user_id = $2 AND status = 'active'`,
        [targetId, realUser.id]
      );
      allowed = rows.length > 0;
    }
    if (!allowed) return res.status(403).json({ error: '접근 권한이 없습니다.' });

    const { rows: targetRows } = await pool.query('SELECT id FROM users WHERE id = $1', [targetId]);
    if (!targetRows.length) return res.status(404).json({ error: '유저 없음' });

    req.session.impersonating_user_id = targetId;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/shares/exit — 전환 해제 (requireAuth만, 어드민 불필요)
// _noAutoSwitch 플래그로 멤버 전용 계정 자동 진입 막기 (세션 동안)
router.post('/shares/exit', requireAuth, (req, res) => {
  delete req.session.impersonating_user_id;
  req.session._noAutoSwitch = true;
  res.json({ ok: true });
});

// GET /api/shares/members — 내 계정에 초대된 멤버 목록 (owner 본인만)
router.get('/shares/members', requireAuth, async (req, res) => {
  try {
    const realUser = req.originalUser || req.user;
    if (req.isSharedAccess) return res.status(403).json({ error: '전환 중에는 멤버 관리가 불가합니다.' });

    const { rows } = await pool.query(
      `SELECT s.id, s.member_email, s.status, s.created_at,
              u.name AS member_name,
              CASE WHEN s.member_user_id IS NOT NULL THEN true ELSE false END AS is_linked
         FROM account_shares s
         LEFT JOIN users u ON u.id = s.member_user_id
        WHERE s.owner_user_id = $1
        ORDER BY s.created_at DESC`,
      [realUser.id]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/shares/members — 멤버 초대
router.post('/shares/members', requireAuth, async (req, res) => {
  try {
    const realUser = req.originalUser || req.user;
    if (req.isSharedAccess) return res.status(403).json({ error: '전환 중에는 멤버를 초대할 수 없습니다.' });

    const { email } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ error: '올바른 이메일을 입력해주세요.' });
    if (email.toLowerCase() === realUser.email.toLowerCase()) {
      return res.status(400).json({ error: '자기 자신은 초대할 수 없습니다.' });
    }

    // 이미 가입된 유저라면 member_user_id 미리 연결
    const { rows: existRows } = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]
    );
    const memberUserId = existRows[0]?.id || null;

    const { rows } = await pool.query(
      `INSERT INTO account_shares (owner_user_id, member_email, member_user_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (owner_user_id, member_email) DO NOTHING
       RETURNING *`,
      [realUser.id, email.toLowerCase(), memberUserId]
    );
    if (!rows.length) return res.status(409).json({ error: '이미 초대된 이메일입니다.' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/shares/members/:id — 멤버 제거
router.delete('/shares/members/:id', requireAuth, async (req, res) => {
  try {
    const realUser = req.originalUser || req.user;
    if (req.isSharedAccess) return res.status(403).json({ error: '전환 중에는 멤버를 제거할 수 없습니다.' });

    const shareId = parseInt(req.params.id);
    const { rowCount } = await pool.query(
      'DELETE FROM account_shares WHERE id = $1 AND owner_user_id = $2',
      [shareId, realUser.id]
    );
    if (!rowCount) return res.status(404).json({ error: '항목 없음 또는 권한 없음' });
    res.json({ ok: true });
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

// GET: 특정 유저의 빈 날짜(report_date 공란/null) 광고데이터 현황 조회
router.get('/admin/empty-date-ads', requireRealAdmin, async (req, res) => {
  try {
    const { user_id } = req.query;
    if (!user_id) return res.status(400).json({ error: 'user_id 필수' });
    const { rows } = await pool.query(`
      SELECT COUNT(*) AS empty_count,
             MIN(created_at) AS first_uploaded,
             MAX(created_at) AS last_uploaded,
             COUNT(DISTINCT campaign_name) AS campaign_count
      FROM ad_reports
      WHERE user_id = $1
        AND (report_date IS NULL OR TRIM(report_date) = '')
    `, [parseInt(user_id)]);
    // 캠페인명 샘플도 같이
    const { rows: samples } = await pool.query(`
      SELECT DISTINCT campaign_name, product_name
      FROM ad_reports
      WHERE user_id = $1 AND (report_date IS NULL OR TRIM(report_date) = '')
      LIMIT 10
    `, [parseInt(user_id)]);
    res.json({ ...rows[0], samples });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PUT: 특정 유저의 빈 날짜 광고데이터를 지정 날짜로 일괄 채움
router.put('/admin/fill-ad-date', requireRealAdmin, async (req, res) => {
  try {
    const { user_id, target_date } = req.body;
    if (!user_id || !target_date) return res.status(400).json({ error: 'user_id, target_date 필수' });
    // target_date 형식 검증 (YYYY-MM-DD)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(target_date)) return res.status(400).json({ error: 'target_date는 YYYY-MM-DD 형식이어야 합니다' });
    const { rows } = await pool.query(`
      UPDATE ad_reports
      SET report_date = $2
      WHERE user_id = $1 AND (report_date IS NULL OR TRIM(report_date) = '')
      RETURNING id
    `, [parseInt(user_id), target_date]);
    console.log(`[admin/fill-ad-date] user=${user_id} 날짜=${target_date} 채움=${rows.length}건 by admin=${req.originalAdmin?.id || req.user.id}`);
    res.json({ updated: rows.length, target_date });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET: 특정 유저의 주문 + 적용가능 할인 진단
// /api/admin/discount-debug?email=xxx&date=2026-06-06
router.get('/admin/discount-debug', requireRealAdmin, async (req, res) => {
  try {
    const { email, user_id, date } = req.query;
    let uid = user_id;
    if (!uid && email) {
      const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
      if (!rows[0]) return res.status(404).json({ error: '해당 이메일 유저 없음' });
      uid = rows[0].id;
    }
    if (!uid) return res.status(400).json({ error: 'email 또는 user_id 필수' });
    uid = parseInt(uid);

    // 해당 날짜 주문
    const { rows: orders } = await pool.query(`
      SELECT id, order_number, order_date, option_id, product_name, option_name,
             payment_amount, shipping_fee, is_excluded, exclusion_type
      FROM orders
      WHERE user_id=$1 AND ($2::text IS NULL OR SUBSTRING(order_date,1,10)=$2)
      ORDER BY order_date
    `, [uid, date || null]);

    // 이 주문들의 option_id 목록
    const optionIds = [...new Set(orders.map(o => o.option_id).filter(Boolean))];

    // 해당 옵션들에 등록된 상시할인가 전체
    const { rows: fixedDiscounts } = optionIds.length ? await pool.query(`
      SELECT option_id, discount_type, discount_amount, start_date, end_date
      FROM fixed_discounts
      WHERE user_id=$1 AND option_id = ANY($2)
      ORDER BY option_id, discount_type, start_date
    `, [uid, optionIds]) : { rows: [] };

    // 해당 옵션들에 적용되는 쿠폰 (option_ids JSONB에 포함)
    const { rows: coupons } = optionIds.length ? await pool.query(`
      SELECT coupon_id, name, coupon_type, discount_amount, start_at, end_at, option_ids
      FROM coupons
      WHERE user_id=$1 AND option_ids ?| $2::text[]
      ORDER BY coupon_type, discount_amount DESC
    `, [uid, optionIds]) : { rows: [] };

    // 유저의 discount_mode
    const { rows: u } = await pool.query('SELECT discount_mode FROM users WHERE id=$1', [uid]);

    res.json({
      user_id: uid,
      discount_mode: u[0]?.discount_mode || 'coupon',
      order_count: orders.length,
      orders,
      option_ids: optionIds,
      fixed_discounts: fixedDiscounts,
      coupons
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET: 특정 주문 1건에 대해 각 상시할인가의 매칭 여부를 DB가 실제 판정
// /api/admin/discount-match?user_id=25&order_id=23719
router.get('/admin/discount-match', requireRealAdmin, async (req, res) => {
  try {
    const { user_id, order_id } = req.query;
    if (!user_id || !order_id) return res.status(400).json({ error: 'user_id, order_id 필수' });
    const { rows } = await pool.query(`
      WITH ord AS (
        SELECT id, order_date, option_id,
          CASE WHEN order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}'
               THEN TO_TIMESTAMP(SUBSTRING(order_date,1,19),'YYYY-MM-DD HH24:MI:SS')::timestamp AT TIME ZONE 'Asia/Seoul'
               ELSE (TO_DATE(SUBSTRING(order_date,1,10),'YYYY-MM-DD')::TIMESTAMP + INTERVAL '23 hours 59 minutes 59 seconds') AT TIME ZONE 'Asia/Seoul'
          END AS ord_end_ts,
          CASE WHEN order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}'
               THEN TO_TIMESTAMP(SUBSTRING(order_date,1,19),'YYYY-MM-DD HH24:MI:SS')::timestamp AT TIME ZONE 'Asia/Seoul'
               ELSE TO_DATE(SUBSTRING(order_date,1,10),'YYYY-MM-DD')::TIMESTAMP AT TIME ZONE 'Asia/Seoul'
          END AS ord_start_ts
        FROM orders WHERE id=$2 AND user_id=$1
      )
      SELECT fd.discount_type, fd.discount_amount, fd.start_date, fd.end_date,
             ord.order_date, ord.ord_start_ts, ord.ord_end_ts,
             (fd.start_date <= ord.ord_end_ts) AS start_ok,
             (fd.end_date IS NULL OR fd.end_date >= ord.ord_start_ts) AS end_ok,
             (fd.start_date <= ord.ord_end_ts AND (fd.end_date IS NULL OR fd.end_date >= ord.ord_start_ts)) AS matched
      FROM fixed_discounts fd
      CROSS JOIN ord
      WHERE fd.user_id=$1 AND fd.option_id = ord.option_id
      ORDER BY fd.discount_type, fd.start_date
    `, [parseInt(user_id), parseInt(order_id)]);
    res.json({ rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/admin/product-group-debug?email=xxx&q=감자
router.get('/admin/product-group-debug', requireRealAdmin, async (req, res) => {
  try {
    const { email, user_id, q } = req.query;
    let uid = user_id;
    if (!uid && email) {
      const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
      if (!rows[0]) return res.status(404).json({ error: '유저 없음' });
      uid = rows[0].id;
    }
    if (!uid || !q) return res.status(400).json({ error: 'email(또는 user_id)와 q 필수' });
    uid = parseInt(uid);

    // 주문서 상품
    const { rows: orders } = await pool.query(`
      SELECT DISTINCT option_id, product_name, option_name, display_product_id
      FROM orders
      WHERE user_id=$1 AND product_name ILIKE '%'||$2||'%'
      ORDER BY product_name, option_name
    `, [uid, q]);

    // 광고 상품
    const { rows: ads } = await pool.query(`
      SELECT DISTINCT option_id, product_name
      FROM ad_reports
      WHERE user_id=$1 AND product_name ILIKE '%'||$2||'%'
      ORDER BY product_name
    `, [uid, q]);

    res.json({
      user_id: uid,
      query: q,
      orders_products: orders.map(o => ({
        option_id: o.option_id,
        product_name: o.product_name,
        product_name_len: (o.product_name||'').length,
        option_name: o.option_name,
        display_product_id: o.display_product_id,
      })),
      ad_products: ads.map(a => ({
        option_id: a.option_id,
        product_name: a.product_name,
        product_name_len: (a.product_name||'').length,
      })),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE: 특정 유저의 빈 날짜(report_date 공란/null) 광고데이터 일괄 삭제
router.delete('/admin/empty-date-ads', requireRealAdmin, async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id 필수' });
    const { rows } = await pool.query(`
      DELETE FROM ad_reports
      WHERE user_id = $1 AND (report_date IS NULL OR TRIM(report_date) = '')
      RETURNING id
    `, [parseInt(user_id)]);
    console.log(`[admin/empty-date-ads DELETE] user=${user_id} 삭제=${rows.length}건 by admin=${req.originalAdmin?.id || req.user.id}`);
    res.json({ deleted: rows.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET: 특정 유저/날짜의 광고데이터 중복 의심 행 진단 (option_id+keyword 기준 카운트)
router.get('/admin/ad-dupe-check', requireRealAdmin, async (req, res) => {
  try {
    const { user_id, date } = req.query;
    if (!user_id || !date) return res.status(400).json({ error: 'user_id, date 필수' });
    // 해당 날짜 전체 행수 + 광고비 합계
    const { rows: total } = await pool.query(`
      SELECT COUNT(*) AS row_count,
             COALESCE(SUM(ad_cost),0) AS sum_ad_cost,
             COALESCE(SUM(actual_ad_cost),0) AS sum_actual_ad_cost,
             COUNT(DISTINCT option_id) AS distinct_options
      FROM ad_reports
      WHERE user_id=$1 AND report_date=$2
    `, [parseInt(user_id), date]);
    // option_id+keyword+ad_placement 조합별 중복 카운트 (2건 이상인 것만)
    const { rows: dupes } = await pool.query(`
      SELECT option_id, keyword, ad_placement, COUNT(*) AS cnt, SUM(ad_cost) AS sum_cost
      FROM ad_reports
      WHERE user_id=$1 AND report_date=$2
      GROUP BY option_id, keyword, ad_placement
      HAVING COUNT(*) > 1
      ORDER BY cnt DESC
      LIMIT 50
    `, [parseInt(user_id), date]);
    res.json({ ...total[0], dupe_groups: dupes.length, dupes });
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

// ─── 미발주 주문 도매처별 분류 ────────────────────────────────────────────────
router.get('/orders/for-dispatch', requireAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const params = [req.user.id];
    let q = `
      SELECT o.id, o.order_number, o.order_date, o.product_name, o.option_name, o.option_id,
             o.quantity, o.recipient_name_masked AS recipient_name, o.recipient_phone_masked AS recipient_phone,
             o.recipient_address_masked AS recipient_address, o.recipient_zipcode, o.delivery_msg,
             om.supplier_id, om.supplier_product_name, om.supplier_option_name,
             ws.name AS supplier_name, ws.form_key AS supplier_form_key
      FROM orders o
      LEFT JOIN order_mappings om ON om.user_id=o.user_id AND om.option_id=o.option_id
      LEFT JOIN wholesale_suppliers ws ON ws.id=om.supplier_id
      WHERE o.user_id=$1 AND o.ordered_at IS NULL AND o.is_excluded IS NOT TRUE`;
    // from/to가 시간 포함('YYYY-MM-DD HH:MM:SS')이면 앞19자 비교, 날짜만이면 앞10자 비교
    if (from) { params.push(from); q += ` AND SUBSTRING(o.order_date,1,${from.length > 10 ? 19 : 10}) >= $${params.length}`; }
    if (to)   { params.push(to);   q += ` AND SUBSTRING(o.order_date,1,${to.length   > 10 ? 19 : 10}) <= $${params.length}`; }
    q += ' ORDER BY om.supplier_id NULLS LAST, o.product_name';
    const { rows } = await pool.query(q, params);
    const groups = {}; const unmatched = [];
    for (const r of rows) {
      if (!r.supplier_id) { unmatched.push(r); continue; }
      if (!groups[r.supplier_id]) groups[r.supplier_id] = { supplier_id: r.supplier_id, supplier_name: r.supplier_name, form_key: r.supplier_form_key || null, orders: [] };
      groups[r.supplier_id].orders.push(r);
    }
    res.json({ groups: Object.values(groups), unmatched, total: rows.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/orders/option-first-date', requireAuth, async (req, res) => {
  try {
    const optionId = String(req.query.option_id || '').trim();
    if (!optionId) return res.status(400).json({ error: 'option_id 필수' });
    const { rows } = await pool.query(
      `SELECT MIN(SUBSTRING(order_date,1,10)) AS first_date
         FROM orders
        WHERE user_id = $1 AND option_id = $2 AND is_excluded IS NOT TRUE`,
      [req.user.id, optionId]
    );
    res.json({ option_id: optionId, first_date: rows[0]?.first_date || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
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
      '우편번호':            r.recipient_zipcode || '',
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
  const COLS  = 26; // INSERT 컬럼 수 (우편번호 + 배송메시지 포함)
  let inserted = 0;

  try {
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const placeholders = [];
      const params       = [];
      let p = 1;

      for (const o of batch) {
        placeholders.push(
          `($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7},$${p+8},$${p+9},$${p+10},$${p+11},$${p+12},$${p+13},$${p+14},$${p+15},$${p+16},$${p+17},$${p+18},$${p+19},$${p+20},$${p+21},$${p+22},$${p+23},$${p+24},$${p+25})`
        );
        params.push(
          req.user.id,                                                          // $1  user_id
          o['주문번호'] || '',                                                   // $2  order_number
          o['묶음배송번호'] || '',                                               // $3  bundle_number
          o['주문일'] || '',                                                     // $4  order_date
          o['등록상품명'] || '',                                                 // $5  product_name
          o['등록옵션명'] || '',                                                 // $6  option_name
          o['노출상품명(옵션명)'] || o['노출상품명'] || '',                       // $7  display_name
          o['노출상품ID'] || '',                                                 // $8  display_product_id
          o['옵션ID'] || '',                                                     // $9  option_id
          parseInt(o['결제액']) || 0,                                            // $10 payment_amount
          parseInt(o['배송비']) || 0,                                            // $11 shipping_fee
          parseInt(o['구매수(수량)']) || parseInt(o['구매수량']) || 1,            // $12 quantity
          parseInt(o['옵션판매가(판매단가)']) || parseInt(o['옵션판매가']) || 0,  // $13 unit_price
          o['택배사'] || '',                                                     // $14 courier
          o['운송장번호'] || '',                                                 // $15 tracking_number
          o['출고일'] || '',                                                     // $16 shipped_date
          o['배송완료일'] || '',                                                 // $17 delivered_date
          o['구매확정일자'] || '',                                               // $18 confirmed_date
          o['결제위치'] || '',                                                   // $19 payment_location
          o['배송유형'] || '',                                                   // $20 delivery_type
          o['구매자'] || '',                                                     // $21 buyer_masked
          o['수취인이름'] || '',                                                 // $22 recipient_name_masked
          o['수취인전화번호'] || '',                                             // $23 recipient_phone_masked
          o['수취인 주소'] || o['수취인주소'] || '',                              // $24 recipient_address_masked
          o['우편번호'] || '',                                                   // $25 recipient_zipcode
          o['배송메세지'] || o['배송메시지'] || '',                               // $26 delivery_msg
        );
        p += COLS;
      }

      const r = await pool.query(
        `INSERT INTO orders
         (user_id,order_number,bundle_number,order_date,product_name,option_name,
          display_name,display_product_id,option_id,payment_amount,shipping_fee,
          quantity,unit_price,courier,tracking_number,shipped_date,delivered_date,
          confirmed_date,payment_location,delivery_type,buyer_masked,
          recipient_name_masked,recipient_phone_masked,recipient_address_masked,
          recipient_zipcode,delivery_msg)
         VALUES ${placeholders.join(',')}
         ON CONFLICT (user_id, order_number) DO UPDATE SET
           buyer_masked             = EXCLUDED.buyer_masked,
           recipient_name_masked    = EXCLUDED.recipient_name_masked,
           recipient_phone_masked   = EXCLUDED.recipient_phone_masked,
           recipient_address_masked = EXCLUDED.recipient_address_masked,
           recipient_zipcode        = EXCLUDED.recipient_zipcode,
           delivery_msg             = EXCLUDED.delivery_msg`,
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

// 광고 심층분석 - 옵션별 집계 + 손익분기 ROAS
// GET /api/ad-analysis/options?start=YYYY-MM-DD&end=YYYY-MM-DD
router.get('/ad-analysis/options', requireAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    const params = [req.user.id];
    let q = `
      SELECT option_id,
             MAX(product_name) AS product_name,
             SUM(impressions)  AS impressions,
             SUM(clicks)       AS clicks,
             SUM(ad_cost)      AS ad_cost,
             SUM(orders_1d)    AS orders_1d,
             SUM(revenue_1d)   AS revenue_1d,
             SUM(orders_14d)   AS orders_14d,
             SUM(revenue_14d)  AS revenue_14d
      FROM ad_reports WHERE user_id=$1`;
    if (start) { params.push(start); q += ` AND report_date >= $${params.length}`; }
    if (end)   { params.push(end);   q += ` AND report_date <= $${params.length}`; }
    q += ' GROUP BY option_id ORDER BY SUM(ad_cost) DESC';
    const { rows } = await pool.query(q, params);

    // calculateProfit으로 by_product 가져와 손익분기 ROAS 계산
    const profitResult = await calculateProfit(req.user.id, start || null, end || null, 'month');
    const byProductMap = {};
    (profitResult.by_product || []).forEach(bp => {
      byProductMap[bp.option_id] = bp;
    });

    res.json(rows.map(r => {
      const bp = byProductMap[r.option_id];
      let margin_rate = null, breakeven_roas = null, matched = false, option_name = '';
      let status = 'no_sales'; // 기본: 판매 없음

      if (bp) {
        option_name = bp.option_name || '';
        const revBefore = bp.revenue_before || 0;
        const revAfter  = bp.revenue_after  || 0;
        const comm      = bp.commission     || 0;
        const cost      = bp.total_cost     || 0;
        const adOnly    = bp.ad_only        || false;
        if (revBefore <= 0) {
          status = 'no_sales';
        } else if (cost === 0 && !adOnly) {
          status = 'no_cost';
        } else {
          // 광고비 전 순수익 = revenue_after - commission - total_cost + commission/11 (매입세액공제, 광고비분 제외)
          const profitBeforeAd = revAfter - comm - cost + comm / 11;
          margin_rate    = profitBeforeAd / revBefore;
          breakeven_roas = margin_rate > 0 ? Math.round(1 / margin_rate * 100) : null;
          matched = true;
          status  = 'ok';
        }
      } // bp 없으면 status = 'no_sales' (by_product에 아예 없음 = 판매 없음)

      return {
        option_id:      r.option_id,
        product_name:   r.product_name,
        option_name,
        impressions:    parseInt(r.impressions)   || 0,
        clicks:         parseInt(r.clicks)        || 0,
        ad_cost:        parseFloat(r.ad_cost)     || 0,
        orders_1d:      parseInt(r.orders_1d)     || 0,
        revenue_1d:     parseFloat(r.revenue_1d)  || 0,
        orders_14d:     parseInt(r.orders_14d)    || 0,
        revenue_14d:    parseFloat(r.revenue_14d) || 0,
        margin_rate,
        breakeven_roas,
        matched,
        status,
      };
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 광고 심층분석 - 키워드별 집계
// GET /api/ad-analysis/keywords?start=YYYY-MM-DD&end=YYYY-MM-DD
router.get('/ad-analysis/keywords', requireAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    const params = [req.user.id];
    let q = `
      SELECT campaign_name, keyword,
             SUM(impressions) AS impressions,
             SUM(clicks)      AS clicks,
             SUM(ad_cost)     AS ad_cost,
             SUM(orders_1d)   AS orders_1d,
             SUM(revenue_1d)  AS revenue_1d,
             SUM(orders_14d)  AS orders_14d,
             SUM(revenue_14d) AS revenue_14d
      FROM ad_reports
      WHERE user_id=$1 AND keyword IS NOT NULL AND TRIM(keyword) <> '' AND TRIM(keyword) <> '-'`;
    if (start) { params.push(start); q += ` AND report_date >= $${params.length}`; }
    if (end)   { params.push(end);   q += ` AND report_date <= $${params.length}`; }
    q += ' GROUP BY campaign_name, keyword ORDER BY campaign_name, SUM(ad_cost) DESC';
    const { rows } = await pool.query(q, params);
    res.json(rows.map(r => ({
      campaign_name: r.campaign_name || '(캠페인 미지정)',
      keyword:     r.keyword,
      impressions: parseInt(r.impressions)   || 0,
      clicks:      parseInt(r.clicks)        || 0,
      ad_cost:     parseFloat(r.ad_cost)     || 0,
      orders_1d:   parseInt(r.orders_1d)     || 0,
      revenue_1d:  parseFloat(r.revenue_1d)  || 0,
      orders_14d:  parseInt(r.orders_14d)    || 0,
      revenue_14d: parseFloat(r.revenue_14d) || 0,
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// 광고 심층분석 - 노출영역별 집계
// GET /api/ad-analysis/placements?start=YYYY-MM-DD&end=YYYY-MM-DD
router.get('/ad-analysis/placements', requireAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    const params = [req.user.id];
    let q = `
      SELECT COALESCE(NULLIF(ad_placement,''),'(미분류)') AS placement,
             SUM(impressions) AS impressions,
             SUM(clicks)      AS clicks,
             SUM(ad_cost)     AS ad_cost,
             SUM(orders_1d)   AS orders_1d,
             SUM(revenue_1d)  AS revenue_1d,
             SUM(orders_14d)  AS orders_14d,
             SUM(revenue_14d) AS revenue_14d
      FROM ad_reports WHERE user_id=$1`;
    if (start) { params.push(start); q += ` AND report_date >= $${params.length}`; }
    if (end)   { params.push(end);   q += ` AND report_date <= $${params.length}`; }
    q += ` GROUP BY COALESCE(NULLIF(ad_placement,''),'(미분류)') ORDER BY SUM(ad_cost) DESC`;
    const { rows } = await pool.query(q, params);
    res.json(rows.map(r => ({
      placement:   r.placement,
      impressions: parseInt(r.impressions)   || 0,
      clicks:      parseInt(r.clicks)        || 0,
      ad_cost:     parseFloat(r.ad_cost)     || 0,
      orders_1d:   parseInt(r.orders_1d)     || 0,
      revenue_1d:  parseFloat(r.revenue_1d)  || 0,
      orders_14d:  parseInt(r.orders_14d)    || 0,
      revenue_14d: parseFloat(r.revenue_14d) || 0,
    })));
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
    coupon_type:     r.coupon_type || 'instant',
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
  const { coupon_id, name, discount_amount, start_at, end_at, option_ids, coupon_type } = req.body;
  if (!name) return res.status(400).json({ error: 'name 필수' });
  const validType = coupon_type === 'download' ? 'download' : 'instant';
  try {
    const { rows } = await pool.query(
      `INSERT INTO coupons (user_id,coupon_id,name,discount_amount,start_at,end_at,option_ids,coupon_type)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [
        req.user.id,
        coupon_id || null,
        name,
        discount_amount || 0,
        start_at || null,
        end_at   || null,
        JSON.stringify(Array.isArray(option_ids) ? option_ids : []),
        validType,
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
        const validType = c.coupon_type === 'download' ? 'download' : 'instant';
        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5},$${p+6},$${p+7})`);
        params.push(
          req.user.id,
          c.coupon_id       || null,
          c.name,
          c.discount_amount || 0,
          c.start_at        || null,
          c.end_at          || null,
          JSON.stringify(Array.isArray(c.option_ids) ? c.option_ids : []),
          validType,
        );
        p += 8;
      }

      if (placeholders.length > 0) {
        const result = await pool.query(
          `INSERT INTO coupons (user_id,coupon_id,name,discount_amount,start_at,end_at,option_ids,coupon_type)
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
  const { coupon_id, name, discount_amount, start_at, end_at, option_ids, coupon_type } = req.body;
  if (!name) return res.status(400).json({ error: 'name 필수' });
  const validType = coupon_type === 'download' ? 'download' : 'instant';
  try {
    const { rows } = await pool.query(
      `UPDATE coupons
       SET coupon_id=$3, name=$4, discount_amount=$5, start_at=$6, end_at=$7, option_ids=$8, coupon_type=$9
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
        validType,
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
    discount_type:   r.discount_type || 'instant',
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

// 동일 option_id + discount_type 진행중 이력 종료 (트랜잭션 client 사용)
async function autoCloseActiveDiscounts(client, userId, optionId, newStartDate, discountType) {
  const oid = String(optionId);
  const dtype = discountType === 'download' ? 'download' : 'instant';
  const result = await client.query(
    `UPDATE fixed_discounts
     SET end_date = $3::TIMESTAMPTZ - INTERVAL '1 second'
     WHERE user_id = $1
       AND option_id = $2
       AND discount_type = $4
       AND (end_date IS NULL OR end_date >= $3::TIMESTAMPTZ)`,
    [userId, oid, newStartDate, dtype]
  );
  console.log(`[autoClose] user=${userId} option_id=${oid} type=${dtype} start=${newStartDate} → closed ${result.rowCount}건`);
  return result.rowCount;
}

router.post('/fixed-discounts', requireAuth, async (req, res) => {
  const { option_id, discount_amount, start_date, end_date, discount_type } = req.body;
  if (!option_id)                               return res.status(400).json({ error: 'option_id 필수' });
  if (!discount_amount || discount_amount <= 0) return res.status(400).json({ error: '할인금액 필수' });
  if (!start_date)                              return res.status(400).json({ error: '시작일 필수' });
  const oid   = String(option_id);
  const dtype = discount_type === 'download' ? 'download' : 'instant';
  console.log(`[fixed-discounts POST] user=${req.user.id} option_id=${oid} type=${dtype} start_date=${start_date}`);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await autoCloseActiveDiscounts(client, req.user.id, oid, start_date, dtype);
    // ON CONFLICT DO UPDATE: start_date+discount_type 충돌 시 갱신 (ROLLBACK 방지)
    const { rows } = await client.query(
      `INSERT INTO fixed_discounts (user_id,option_id,discount_amount,start_date,end_date,discount_type)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (user_id,option_id,start_date,discount_type)
       DO UPDATE SET discount_amount = EXCLUDED.discount_amount,
                     end_date        = EXCLUDED.end_date
       RETURNING *`,
      [req.user.id, oid, discount_amount, start_date, end_date || null, dtype]
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

      // 배치 내 고유 (option_id, discount_type)별 자동 종료 처리
      const uniqueKeys = [...new Set(validItems.map(it => `${it.option_id}||${it.discount_type || 'instant'}`))];
      for (const key of uniqueKeys) {
        const [oid, dtype] = key.split('||');
        const earliest = validItems
          .filter(it => it.option_id === oid && (it.discount_type || 'instant') === dtype)
          .map(it => it.start_date)
          .sort()[0];
        await autoCloseActiveDiscounts(client, req.user.id, oid, earliest, dtype);
      }

      const placeholders = [];
      const params = [];
      let p = 1;
      for (const item of validItems) {
        const dtype = item.discount_type === 'download' ? 'download' : 'instant';
        placeholders.push(`($${p},$${p+1},$${p+2},$${p+3},$${p+4},$${p+5})`);
        params.push(req.user.id, item.option_id, item.discount_amount, item.start_date, item.end_date || null, dtype);
        p += 6;
      }
      const result = await client.query(
        `INSERT INTO fixed_discounts (user_id,option_id,discount_amount,start_date,end_date,discount_type)
         VALUES ${placeholders.join(',')}
         ON CONFLICT (user_id,option_id,start_date,discount_type) DO NOTHING
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
  const { option_id, discount_amount, start_date, end_date, discount_type } = req.body;
  if (!option_id)                          return res.status(400).json({ error: 'option_id 필수' });
  if (!discount_amount || discount_amount <= 0) return res.status(400).json({ error: '할인금액 필수' });
  if (!start_date)                         return res.status(400).json({ error: '시작일 필수' });
  const dtype = discount_type === 'download' ? 'download' : 'instant';
  try {
    const { rows } = await pool.query(
      `UPDATE fixed_discounts SET option_id=$3,discount_amount=$4,start_date=$5,end_date=$6,discount_type=$7
       WHERE id=$1 AND user_id=$2 RETURNING *`,
      [req.params.id, req.user.id, option_id, discount_amount, start_date, end_date || null, dtype]
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
        // option_id가 새로운 경우: 새 행으로 INSERT (동일 상품명+옵션명이어도 option_id 다르면 공존)
        // ON CONFLICT는 pnm_unique_idx (user_id, registered_name, option_name, COALESCE(option_id,'')) 기준
        const { rows } = await pool.query(
          `INSERT INTO product_name_mapping
             (user_id, registered_name, option_name, b2b_name, b2b_unit, option_id)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (user_id, registered_name, option_name, COALESCE(option_id,''))
             DO UPDATE SET b2b_name=EXCLUDED.b2b_name, b2b_unit=EXCLUDED.b2b_unit
           RETURNING *`,
          [req.user.id, registered_name, option_name, b2b_name, b2b_unit, oid]
        );
        row = rows[0];
      }
    } else {
      const { rows } = await pool.query(
        `INSERT INTO product_name_mapping (user_id, registered_name, option_name, b2b_name, b2b_unit)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (user_id, registered_name, option_name, COALESCE(option_id,''))
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

        // 발주용: 원본 저장 (개인정보는 14일 후 자동 마스킹 스케줄러에서 처리)
        const buyerOrig     = sheet.orderer?.name || '';
        const recipientOrig = sheet.receiver?.name || '';
        const phoneOrig     = sheet.receiver?.safeNumber || sheet.receiver?.phone || '';
        const addrOrig      = sheet.receiver?.addr1 || '';
        const zipcodeOrig   = sheet.receiver?.postCode || sheet.receiver?.zipCode || sheet.receiver?.remotePostCode || '';
        const deliveryMsg   = sheet.parcelPrintMessage || sheet.deliveryMessage || sheet.shippingMessage || '';

        try {
          const upsertRes = await pool.query(
            `INSERT INTO orders (
              user_id, order_number, bundle_number, order_date,
              product_name, option_name, display_name, display_product_id, option_id,
              payment_amount, shipping_fee, quantity, unit_price,
              buyer_masked, recipient_name_masked, recipient_phone_masked, recipient_address_masked,
              recipient_zipcode, delivery_msg,
              is_excluded, exclusion_type
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,FALSE,'normal')
            ON CONFLICT (user_id, order_number) DO UPDATE SET
              display_product_id = CASE
                WHEN orders.display_product_id IS NULL OR orders.display_product_id = ''
                THEN EXCLUDED.display_product_id ELSE orders.display_product_id END,
              option_id = CASE
                WHEN orders.option_id IS NULL OR orders.option_id = ''
                THEN EXCLUDED.option_id ELSE orders.option_id END,
              display_name = CASE
                WHEN orders.display_name IS NULL OR orders.display_name = ''
                THEN EXCLUDED.display_name ELSE orders.display_name END,
              buyer_masked             = EXCLUDED.buyer_masked,
              recipient_name_masked    = EXCLUDED.recipient_name_masked,
              recipient_phone_masked   = EXCLUDED.recipient_phone_masked,
              recipient_address_masked = EXCLUDED.recipient_address_masked,
              recipient_zipcode        = EXCLUDED.recipient_zipcode,
              delivery_msg             = EXCLUDED.delivery_msg
            RETURNING id, (xmax = 0) AS is_insert`,
            [
              req.user.id, orderNumber, bundleNumber, orderDate,
              productName, optionName, displayName, displayProductId, optionId,
              paymentAmt, shippingFee, qty, unitPrice,
              buyerOrig, recipientOrig, phoneOrig, addrOrig, zipcodeOrig, deliveryMsg,
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
function wsRow(r) {
  // api_client_secret_enc은 절대 응답에 포함하지 않음
  const masked = r.api_client_id
    ? r.api_client_id.slice(0, 4) + '****'
    : null;
  return {
    id: r.id,
    name: r.name,
    url: r.url,
    created_at: r.created_at,
    api_linked: !!r.api_linked,
    api_type: r.api_type || null,
    api_client_id_masked: masked,
    form_key: r.form_key || null,
  };
}

router.get('/wholesale-suppliers', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM wholesale_suppliers WHERE user_id=$1 ORDER BY created_at ASC',
      [req.user.id]
    );
    res.json(rows.map(wsRow));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/wholesale-suppliers', requireAuth, async (req, res) => {
  const { name, url, api_type, api_client_id, api_client_secret, form_key } = req.body;
  if (!name || !url) return res.status(400).json({ error: '이름과 URL을 입력하세요' });
  try {
    let secretEnc = null, apiLinked = false;
    if (api_type && api_client_id && api_client_secret) {
      secretEnc = encryptSecret(api_client_secret);
      apiLinked = true;
    }
    const { rows } = await pool.query(
      `INSERT INTO wholesale_suppliers (user_id,name,url,api_type,api_client_id,api_client_secret_enc,api_linked,form_key)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.id, name.trim(), url.trim(), api_type || null, api_client_id || null, secretEnc, apiLinked, form_key || null]
    );
    res.json(wsRow(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.put('/wholesale-suppliers/:id', requireAuth, async (req, res) => {
  const { name, url, api_type, api_client_id, api_client_secret, form_key } = req.body;
  if (!name || !url) return res.status(400).json({ error: '이름과 URL을 입력하세요' });
  try {
    // 기존 레코드 조회 (secret 유지 여부 판단)
    const { rows: existing } = await pool.query(
      'SELECT * FROM wholesale_suppliers WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!existing.length) return res.status(404).json({ error: '항목 없음' });
    const prev = existing[0];
    // client_id: 비우면 기존 유지
    const finalClientId = (api_client_id && api_client_id.trim()) ? api_client_id.trim() : prev.api_client_id;
    // secret: 비우면 기존 유지
    let secretEnc = prev.api_client_secret_enc;
    if (api_client_secret && api_client_secret.trim()) {
      secretEnc = encryptSecret(api_client_secret.trim());
    }
    // api_linked: api_type 있고 id/secret 둘 다 존재하면 true, api_type 비우면 초기화
    let apiLinked = false;
    if (!api_type) { secretEnc = null; apiLinked = false; }
    else if (api_type && finalClientId && secretEnc) { apiLinked = true; }
    const { rows } = await pool.query(
      `UPDATE wholesale_suppliers
       SET name=$1, url=$2, api_type=$3, api_client_id=$4, api_client_secret_enc=$5, api_linked=$6, form_key=$7
       WHERE id=$8 AND user_id=$9 RETURNING *`,
      [name.trim(), url.trim(), api_type || null, finalClientId || null, secretEnc, apiLinked, form_key || null, req.params.id, req.user.id]
    );
    res.json(wsRow(rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/wholesale-suppliers/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM wholesale_suppliers WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 발주 양식 정의 반환 ───────────────────────────────────────────────────────
router.get('/order-forms', requireAuth, (req, res) => {
  res.json({ forms: ORDER_FORMS });
});

// ── 발주 완료 기록 ────────────────────────────────────────────────────────────
router.post('/orders/mark-dispatched', requireAuth, async (req, res) => {
  const { order_ids, supplier_id } = req.body;
  if (!Array.isArray(order_ids) || !order_ids.length) return res.status(400).json({ error: 'order_ids 필요' });
  try {
    await pool.query(
      `UPDATE orders SET ordered_at=NOW(), ordered_supplier_id=$1
       WHERE id = ANY($2::int[]) AND user_id=$3`,
      [supplier_id || null, order_ids.map(Number), req.user.id]
    );
    res.json({ ok: true, count: order_ids.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 도매처 연결 테스트 ─────────────────────────────────────────────────────────
router.post('/wholesale-suppliers/:id/test', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM wholesale_suppliers WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ ok: false, error: '도매처를 찾을 수 없습니다.' });
    const supplier = rows[0];
    const cfg = getSupplierApiConfig(supplier);
    if (!cfg) return res.status(400).json({ ok: false, error: 'API 연동 정보가 없습니다.' });
    if (cfg.type === 'adminplus') {
      const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);
      const data = await adminplusGetProducts(token, { limit: '5', status: 'active' });
      const items = data.items || [];
      return res.json({ ok: true, sample_count: items.length, first_name: items[0]?.name || null });
    }
    return res.status(400).json({ ok: false, error: '지원하지 않는 api_type: ' + cfg.type });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
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

// ─── 어드민플러스 연결 테스트 + 서버 outbound IP 확인 ──────────────────────────
router.get('/admin/adminplus-test', requireRealAdmin, async (req, res) => {
  const result = {};

  // 1. 우리 서버 outbound IP 확인 (화이트리스트 등록용)
  try {
    const ipr = await fetch('https://api.ipify.org?format=json');
    const ipj = await ipr.json();
    result.our_outbound_ip = ipj.ip;
  } catch(e) { result.our_outbound_ip = 'IP확인실패: ' + e.message; }

  // 2. 어드민플러스 토큰 발급 + 상품 조회
  try {
    const id = process.env.ADMINPLUS_THEGREEN_CLIENT_ID;
    const secret = process.env.ADMINPLUS_THEGREEN_CLIENT_SECRET;
    if (!id || !secret) { result.error = 'ADMINPLUS 환경변수 미설정'; return res.json(result); }
    const body = new URLSearchParams({ client_id: id, client_secret: secret });
    const tr = await fetch('https://api.adminplus.co.kr/oauth/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString()
    });
    const tj = await tr.json();
    result.token_http = tr.status;
    result.token_success = tj.success;
    result.token_message = tj.message;
    if (tj.success) {
      const pr = await fetch('https://api.adminplus.co.kr/v1/seller/products?limit=5&status=active', {
        headers: { 'Authorization': 'Bearer ' + tj.data.access_token }
      });
      const pj = await pr.json();
      result.products_http = pr.status;
      result.products_success = pj.success;
      result.products_message = pj.message;
      result.sample_count = pj.data?.items?.length || 0;
      result.has_more = pj.data?.has_more;
      result.first_item = pj.data?.items?.[0] || null;
    }
  } catch(e) { result.error = e.message; }

  res.json(result);
});

// ─── 주문 수령인 저장값 디버그 (임시) ────────────────────────────────────────
router.get('/admin/order-recipient-debug', requireRealAdmin, async (req, res) => {
  try {
    const on = req.query.order_number;
    let rows;
    if (on) {
      ({ rows } = await pool.query(
        'SELECT order_number, recipient_name_masked, recipient_phone_masked, recipient_address_masked, recipient_zipcode, delivery_msg, created_at FROM orders WHERE order_number=$1',
        [on]
      ));
    } else {
      ({ rows } = await pool.query(
        'SELECT order_number, recipient_name_masked, recipient_phone_masked, recipient_address_masked, recipient_zipcode, delivery_msg, created_at FROM orders ORDER BY created_at DESC LIMIT 5'
      ));
    }
    res.json({ rows });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 어드민플러스 예치금/적립금 잔액 조회 테스트 ────────────────────────────────
router.get('/admin/adminplus-balance-test', requireRealAdmin, async (req, res) => {
  try {
    const { rows: suppliers } = await pool.query(
      `SELECT * FROM wholesale_suppliers WHERE api_linked=true AND api_type='adminplus'`
    );
    const results = [];
    for (const s of suppliers) {
      try {
        const cfg = getSupplierApiConfig(s);
        const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);
        const bal = await adminplusGetBalance(token);
        results.push({
          supplier: s.name,
          http: bal.http,
          success: bal.success,
          message: bal.message,
          deposit_balance: bal.data?.deposit_balance ?? null,
          point_balance: bal.data?.point_balance ?? null,
        });
      } catch(e) {
        results.push({ supplier: s.name, error: String(e.message) });
      }
    }
    res.json({ results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 도매처 잔액 조회 (저장된 값) ─────────────────────────────────────────────
router.get('/supplier/balances', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT b.*, ws.name AS supplier_name FROM supplier_balances b
       JOIN wholesale_suppliers ws ON ws.id=b.supplier_id
       WHERE b.user_id=$1 ORDER BY b.supplier_id`,
      [req.user.id]
    );
    const { rows: last } = await pool.query(
      'SELECT MAX(fetched_at) AS last FROM supplier_balances WHERE user_id=$1',
      [req.user.id]
    );
    res.json({
      balances: rows.map(r => ({
        supplier_id: r.supplier_id,
        supplier_name: r.supplier_name,
        deposit_balance: Number(r.deposit_balance),
        point_balance: Number(r.point_balance),
      })),
      last_fetched: last[0]?.last || null,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 도매처 잔액 수동 새로고침 ────────────────────────────────────────────────
router.post('/supplier/balances/refresh', requireAuth, async (req, res) => {
  try {
    const r = await fetchSupplierBalancesForUser(req.user.id);
    res.json({ ok: true, results: r, fetched_at: new Date().toISOString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 서버측 단위 추출 ─────────────────────────────────────────────────────────
function extractUnit(name) {
  const m = name && name.match(/(\d+(?:\.\d+)?\s*(?:kg|g|개|봉|박스|팩|묶음|세트))\s*$/i);
  return m ? m[1].replace(/\s+/g, '') : '';
}

// ─── 도매처 상품 동기화 (공유 함수 — 수동/자동 공용) ─────────────────────────
async function syncSupplierProductsForUser(userId) {
  const { rows: suppliers } = await pool.query(
    'SELECT * FROM wholesale_suppliers WHERE user_id=$1 AND api_linked=true AND api_type IS NOT NULL',
    [userId]
  );
  if (!suppliers.length) return { synced: 0, suppliers: [] };
  const status = [];
  let total = 0;
  for (const s of suppliers) {
    try {
      const cfg = getSupplierApiConfig(s);
      if (!cfg || cfg.type !== 'adminplus') { status.push({ name: s.name, ok: false, error: '미지원 타입' }); continue; }
      const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);
      let items = [], cursor = null, pages = 0;
      do {
        const params = { limit: 500, status: 'active' };
        if (cursor) params.cursor = cursor;
        const data = await adminplusGetProducts(token, params);
        items = items.concat(data.items || []);
        cursor = data.has_more ? data.next_cursor : null;
        pages++;
      } while (cursor && pages < 50);
      // 각 상품: 기존 가격과 비교해 변동 이력 기록 후 upsert
      for (const p of items) {
        const unit = extractUnit(p.name || '');
        const dp = p.delivery_policy ? JSON.stringify(p.delivery_policy) : null;
        const newPrice = Number(p.price);
        // 기존 가격 조회 (변동 감지용)
        const { rows: prev } = await pool.query(
          'SELECT price FROM supplier_products WHERE user_id=$1 AND supplier_id=$2 AND product_code=$3',
          [userId, s.id, String(p.product_code)]
        );
        const oldPrice = prev.length ? Number(prev[0].price) : null;
        if (oldPrice !== null && oldPrice !== newPrice) {
          await pool.query(
            'INSERT INTO supplier_price_history (user_id,supplier_id,product_code,name,old_price,new_price) VALUES ($1,$2,$3,$4,$5,$6)',
            [userId, s.id, String(p.product_code), p.name, oldPrice, newPrice]
          );
        }
        await pool.query(
          `INSERT INTO supplier_products (user_id,supplier_id,product_code,name,price,taxable,image,stock,delivery_policy,order_cutoff_time,unit,synced_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
           ON CONFLICT (user_id,supplier_id,product_code) DO UPDATE SET
             name=EXCLUDED.name, price=EXCLUDED.price, taxable=EXCLUDED.taxable, image=EXCLUDED.image,
             stock=EXCLUDED.stock, delivery_policy=EXCLUDED.delivery_policy,
             order_cutoff_time=EXCLUDED.order_cutoff_time, unit=EXCLUDED.unit, synced_at=NOW()`,
          [userId, s.id, String(p.product_code), p.name, p.price, p.taxable,
           p.image, String(p.stock || ''), dp, p.order_cutoff_time, unit]
        );
        total++;
      }
      // 이번 동기화에서 사라진 상품 정리
      const codes = items.map(p => String(p.product_code));
      if (codes.length) {
        await pool.query(
          `DELETE FROM supplier_products WHERE user_id=$1 AND supplier_id=$2 AND product_code <> ALL($3)`,
          [userId, s.id, codes]
        );
      }
      status.push({ name: s.name, ok: true, count: items.length });
    } catch(e) { status.push({ name: s.name, ok: false, error: String(e.message) }); }
  }
  return { synced: total, suppliers: status };
}

// ─── 도매처 상품 동기화 엔드포인트 (수동) ──────────────────────────────────────
router.post('/supplier/sync', requireAuth, async (req, res) => {
  try {
    const r = await syncSupplierProductsForUser(req.user.id);
    res.json({ ...r, synced_at: new Date().toISOString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 가격 변동 이력 조회 ────────────────────────────────────────────────────
router.get('/supplier/price-history', requireAuth, async (req, res) => {
  try {
    const days = Math.min(parseInt(req.query.days) || 7, 90);
    const { rows } = await pool.query(
      `SELECT h.*, ws.name AS supplier_name
       FROM supplier_price_history h
       JOIN wholesale_suppliers ws ON ws.id = h.supplier_id
       WHERE h.user_id=$1 AND h.changed_at >= NOW() - INTERVAL '1 day' * $2
       ORDER BY h.changed_at DESC LIMIT 500`,
      [req.user.id, days]
    );
    res.json(rows.map(r => ({
      supplier_name: r.supplier_name,
      product_code:  r.product_code,
      name:          r.name,
      old_price:     Number(r.old_price),
      new_price:     Number(r.new_price),
      diff:          Number(r.new_price) - Number(r.old_price),
      changed_at:    r.changed_at,
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 가격 비교 조회 (DB 캐시 기반, 즉시 응답) ───────────────────────────────
router.get('/supplier/compare', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    const params = [req.user.id];
    let sql = `SELECT sp.*, ws.name AS supplier_name
               FROM supplier_products sp
               JOIN wholesale_suppliers ws ON ws.id = sp.supplier_id
               WHERE sp.user_id = $1`;
    if (q) { params.push('%' + q + '%'); sql += ` AND sp.name ILIKE $${params.length}`; }
    sql += ' ORDER BY sp.name';
    const { rows } = await pool.query(sql, params);
    const { rows: sync } = await pool.query(
      'SELECT MAX(synced_at) AS last FROM supplier_products WHERE user_id=$1', [req.user.id]
    );
    res.json({
      products: rows.map(r => ({
        supplier_id: r.supplier_id, supplier_name: r.supplier_name,
        product_code: r.product_code, name: r.name, price: Number(r.price),
        taxable: r.taxable, image: r.image, stock: r.stock,
        delivery_policy: r.delivery_policy, order_cutoff_time: r.order_cutoff_time, unit: r.unit,
      })),
      last_synced: sync[0]?.last || null,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 도매처 상품 전체 조회 (DB 도매처 기반) ───────────────────────────────────
router.get('/supplier/:supplierId/products', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM wholesale_suppliers WHERE id=$1 AND user_id=$2',
      [req.params.supplierId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: '도매처를 찾을 수 없습니다' });
    const supplier = rows[0];
    if (!supplier.api_linked || !supplier.api_type)
      return res.status(400).json({ error: 'API 연동되지 않은 도매처입니다' });
    const cfg = getSupplierApiConfig(supplier);
    if (!cfg) return res.status(400).json({ error: 'API 설정을 읽을 수 없습니다' });
    if (cfg.type !== 'adminplus')
      return res.status(400).json({ error: '지원하지 않는 API 타입: ' + cfg.type });
    const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);
    let items = [], cursor = null, pages = 0;
    do {
      const params = { limit: 500, status: 'active' };
      if (cursor) params.cursor = cursor;
      const data = await adminplusGetProducts(token, params);
      items = items.concat(data.items || []);
      cursor = data.has_more ? data.next_cursor : null;
      pages++;
    } while (cursor && pages < 50);
    const products = items.map(p => ({
      product_code: p.product_code, name: p.name, price: p.price, taxable: p.taxable,
      image: p.image, shipping_origin: p.shipping_origin, delivery_policy: p.delivery_policy,
      order_cutoff_time: p.order_cutoff_time, stock: p.stock, status: p.status,
      last_updated_date: p.last_updated_date,
    }));
    res.json({ supplier_id: supplier.id, supplier_name: supplier.name, count: products.length, products });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 발주 매칭 CRUD ──────────────────────────────────────────────────────────
router.get('/order-mappings', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT om.*, ws.name AS supplier_name
       FROM order_mappings om
       LEFT JOIN wholesale_suppliers ws ON ws.id = om.supplier_id
       WHERE om.user_id = $1
       ORDER BY om.registered_name, om.option_name`,
      [req.user.id]
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/order-mappings', requireAuth, async (req, res) => {
  const { option_id, registered_name, option_name, supplier_id, supplier_product_name, supplier_option_name } = req.body;
  if (!option_id || !registered_name) return res.status(400).json({ error: 'option_id, registered_name 필수' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO order_mappings
         (user_id, option_id, registered_name, option_name, supplier_id, supplier_product_name, supplier_option_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id, option_id) DO UPDATE SET
         registered_name      = EXCLUDED.registered_name,
         option_name          = EXCLUDED.option_name,
         supplier_id          = EXCLUDED.supplier_id,
         supplier_product_name = EXCLUDED.supplier_product_name,
         supplier_option_name = EXCLUDED.supplier_option_name
       RETURNING *`,
      [req.user.id, option_id, registered_name, option_name || '', supplier_id || null,
       supplier_product_name || '', supplier_option_name || '']
    );
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/order-mappings/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM order_mappings WHERE id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.get('/order-mappings/search-supplier-product', requireAuth, async (req, res) => {
  const { supplier_id, q } = req.query;
  const tokens = (q || '').trim().split(/\s+/).filter(Boolean);
  if (!supplier_id || !tokens.length) return res.json([]);
  try {
    const conds  = tokens.map((_, i) => `name ILIKE $${i + 3}`).join(' AND ');
    const params = [req.user.id, supplier_id, ...tokens.map(t => `%${t}%`)];
    const { rows } = await pool.query(
      `SELECT product_code, name, price, unit
       FROM supplier_products
       WHERE user_id=$1 AND supplier_id=$2 AND ${conds}
       ORDER BY name
       LIMIT 20`,
      params
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 발주 보내는사람 설정 ──────────────────────────────────────────────────────
router.get('/order-sender', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT sender_name, sender_phone, sender_address FROM users WHERE id=$1',
      [req.user.id]
    );
    const u = rows[0] || {};
    res.json({ sender_name: u.sender_name || '', sender_phone: u.sender_phone || '', sender_address: u.sender_address || '' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.post('/order-sender', requireAuth, async (req, res) => {
  const { sender_name, sender_phone, sender_address } = req.body;
  try {
    await pool.query(
      'UPDATE users SET sender_name=$1, sender_phone=$2, sender_address=$3 WHERE id=$4',
      [sender_name || '', sender_phone || '', sender_address || '', req.user.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 14일 경과 주문 수령인 자동 마스킹 ───────────────────────────────────────
async function maskOldOrders() {
  const cutoffStr = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const { rows } = await pool.query(
    `SELECT id, recipient_name_masked, recipient_phone_masked, recipient_address_masked
     FROM orders
     WHERE order_date IS NOT NULL AND order_date <> ''
       AND SUBSTRING(order_date, 1, 10) <= $1
       AND recipient_name_masked IS NOT NULL AND recipient_name_masked <> ''
       AND POSITION('*' IN recipient_name_masked) = 0`,
    [cutoffStr]
  );
  let count = 0;
  for (const r of rows) {
    await pool.query(
      `UPDATE orders SET
         recipient_name_masked    = $1,
         recipient_address_masked = $2,
         recipient_zipcode        = '***'
       WHERE id = $3`,
      [
        maskName(r.recipient_name_masked),
        maskAddr(r.recipient_address_masked),
        r.id,
      ]
    );
    count++;
  }
  return count;
}

// ─── 올웨이즈 주문 대량 저장 ─────────────────────────────────────────────────────
router.post('/alwayz-orders/bulk', requireAuth, async (req, res) => {
  const items = (req.body && req.body.items) || [];
  if (!items.length) return res.json({ inserted: 0 });
  try {
    let inserted = 0;
    const BATCH = 100;
    for (let start = 0; start < items.length; start += BATCH) {
      const batch = items.slice(start, start + BATCH);
      const values = [];
      const params = [];
      let p = 1;
      for (const it of batch) {
        values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
        params.push(
          req.user.id, it.order_id, it.product_id||'', it.bundle_id||'', it.seller_product_code||'',
          it.product_name||'', it.option_name||'', it.quantity||1, it.product_price||0, it.delivery_fee||0,
          it.extra_support||0, it.coupon_alwayz||0, it.coupon_seller||0, it.coupon_total||0, it.settlement_amount||0,
          it.address||'', it.zipcode||'', it.entrance_password||'', it.receive_method||'', it.recipient||'',
          it.recipient_phone||'', it.order_date||'', it.courier||'', it.tracking_number||''
        );
      }
      const q = `INSERT INTO alwayz_orders
        (user_id, order_id, product_id, bundle_id, seller_product_code, product_name, option_name, quantity,
         product_price, delivery_fee, extra_support, coupon_alwayz, coupon_seller, coupon_total, settlement_amount,
         address, zipcode, entrance_password, receive_method, recipient, recipient_phone, order_date, courier, tracking_number)
        VALUES ${values.join(',')}
        ON CONFLICT (user_id, order_id, product_id) DO UPDATE SET
          settlement_amount = EXCLUDED.settlement_amount,
          courier = EXCLUDED.courier,
          tracking_number = EXCLUDED.tracking_number`;
      const r = await pool.query(q, params);
      inserted += r.rowCount;
    }
    res.json({ inserted, total: items.length });
  } catch(e) { console.error('[alwayz-orders/bulk]', e.message); res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 주문 목록 조회 (기간 필터, 결제일 기준) ────────────────────────────
router.get('/alwayz-orders', requireAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    const params = [req.user.id];
    let q = `SELECT * FROM alwayz_orders WHERE user_id=$1`;
    if (start) { params.push(start); q += ` AND SUBSTRING(order_date,1,10) >= $${params.length}`; }
    if (end)   { params.push(end);   q += ` AND SUBSTRING(order_date,1,10) <= $${params.length}`; }
    q += ' ORDER BY order_date DESC LIMIT 1000';
    const { rows } = await pool.query(q, params);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 발주 대상조회 + B2B 자동 도매처 매칭 ──────────────────────────────
router.get('/alwayz-orders/for-dispatch', requireAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const params = [req.user.id];
    let df = '';
    if (from) { params.push(from); df += ` AND SUBSTRING(o.order_date,1,10) >= $${params.length}`; }
    if (to)   { params.push(to);   df += ` AND SUBSTRING(o.order_date,1,10) <= $${params.length}`; }

    const q = `
      SELECT o.id, o.order_id, o.order_date, o.product_id, o.product_name, o.option_name,
             o.quantity, o.recipient, o.recipient_phone, o.address, o.zipcode, o.entrance_password,
             pm.b2b_name, pm.b2b_unit,
             (
               SELECT bs.name FROM alwayz_product_mapping pm2
               JOIN b2b_products bp ON bp.user_id=pm2.user_id AND bp.name=pm2.b2b_name AND bp.unit=pm2.b2b_unit
               JOIN b2b_prices pr ON pr.user_id=pm2.user_id AND pr.b2b_product_id=bp.id
                 AND pr.start_date <= CURRENT_DATE AND (pr.end_date IS NULL OR pr.end_date >= CURRENT_DATE)
               JOIN b2b_suppliers bs ON bs.id=pr.supplier_id
               WHERE pm2.user_id=o.user_id AND pm2.product_id=o.product_id AND pm2.option_name=o.option_name
               ORDER BY pr.start_date DESC LIMIT 1
             ) AS supplier_name
      FROM alwayz_orders o
      LEFT JOIN alwayz_product_mapping pm
        ON pm.user_id=o.user_id AND pm.product_id=o.product_id AND pm.option_name=o.option_name
      WHERE o.user_id=$1 AND o.ordered_at IS NULL${df}
      ORDER BY o.product_name
    `;
    const { rows } = await pool.query(q, params);

    const { rows: wsList } = await pool.query(
      `SELECT id, name, COALESCE(form_key,'') AS form_key FROM wholesale_suppliers WHERE user_id=$1`, [req.user.id]
    );
    const wsByName = {};
    wsList.forEach(w => { wsByName[w.name] = w; });

    const groups = {}; const unmatched = [];
    for (const r of rows) {
      if (!r.supplier_name) {
        unmatched.push({ ...r, reason: r.b2b_name ? '진행중 매입가 없음' : 'B2B 미연결' });
        continue;
      }
      const ws = wsByName[r.supplier_name];
      if (!ws || !ws.form_key) {
        unmatched.push({ ...r, supplier_name: r.supplier_name, reason: '발주양식 미지정('+r.supplier_name+')' });
        continue;
      }
      const key = ws.id;
      if (!groups[key]) groups[key] = { supplier_id: ws.id, supplier_name: ws.name, form_key: ws.form_key, orders: [] };
      groups[key].orders.push({
        order_id:         r.order_id,
        product_name:     r.b2b_name,
        option_name:      '',
        quantity:         r.quantity,
        recipient:        r.recipient,
        recipient_phone:  r.recipient_phone,
        address:          r.address,
        zipcode:          r.zipcode,
        delivery_msg:     '',
      });
    }
    res.json({ groups: Object.values(groups), unmatched, total: rows.length });
  } catch(e) { console.error('[alwayz for-dispatch]', e.message); res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 발주완료 표시 ──────────────────────────────────────────────────────
router.post('/alwayz-orders/mark-dispatched', requireAuth, async (req, res) => {
  const { order_ids } = req.body || {};
  if (!Array.isArray(order_ids) || !order_ids.length) return res.status(400).json({ error: 'order_ids 필요' });
  try {
    const { rowCount } = await pool.query(
      `UPDATE alwayz_orders SET ordered_at = NOW() WHERE user_id=$1 AND order_id = ANY($2)`,
      [req.user.id, order_ids]
    );
    res.json({ ok: true, updated: rowCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 송장 수집+매칭 ─────────────────────────────────────────────────────
router.post('/alwayz-orders/collect-invoices', requireAuth, async (req, res) => {
  try {
    const { from, to, dryRun } = req.body || {};
    const params = [req.user.id];
    let df = '';
    if (from) { params.push(from); df += ` AND SUBSTRING(order_date,1,10) >= $${params.length}`; }
    if (to)   { params.push(to);   df += ` AND SUBSTRING(order_date,1,10) <= $${params.length}`; }

    const { rows: orders } = await pool.query(
      `SELECT id, order_id, product_id, order_date, recipient_phone, courier, tracking_number
       FROM alwayz_orders WHERE user_id=$1${df}`, params
    );

    const { rows: linkedSuppliers } = await pool.query(
      `SELECT id FROM wholesale_suppliers WHERE user_id=$1 AND api_linked=true AND api_type='adminplus' ORDER BY id`,
      [req.user.id]
    );
    const invoiceMap = {};
    const supplierErrors = {};
    for (const s of linkedSuppliers) {
      try { invoiceMap[s.id] = await fetchSupplierInvoices(req.user.id, s.id); }
      catch(e) { supplierErrors[s.id] = e.message; invoiceMap[s.id] = []; }
    }
    const allInvoices = Object.values(invoiceMap).flat();

    const matched = []; const unmatched = [];
    for (const o of orders) {
      const ourPhone = normalizePhone(o.recipient_phone);
      const ourOrderId = (o.order_id || '').trim();
      let hit = ourOrderId ? allInvoices.find(inv => inv.customer_order_code && inv.customer_order_code.trim() === ourOrderId) : null;
      if (!hit && ourPhone && ourPhone.length >= 10) {
        hit = allInvoices.find(inv => inv.receiver_phone === ourPhone);
      }
      if (hit) {
        if (!dryRun) {
          await pool.query(
            `UPDATE alwayz_orders SET courier=$1, tracking_number=$2 WHERE id=$3 AND user_id=$4`,
            [hit.shipping_company, hit.tracking_number, o.id, req.user.id]
          );
        }
        matched.push({
          order_id: o.order_id,
          match_by: (ourOrderId && hit.customer_order_code?.trim() === ourOrderId) ? 'order_id' : 'phone',
          shipping_company: hit.shipping_company,
          tracking_number: hit.tracking_number,
        });
      } else {
        unmatched.push({
          order_id: o.order_id,
          our_phone: ourPhone || '(없음)',
          reason: allInvoices.length === 0 ? '수집송장0건(미발송추정)' : '매칭실패(도매처송장에없음)',
        });
      }
    }
    res.json({
      total: orders.length, matched: matched.length, unmatched_count: unmatched.length,
      matched_list: matched, unmatched, supplier_errors: supplierErrors, dryRun: !!dryRun,
    });
  } catch(e) { console.error('[alwayz collect-invoices]', e.message); res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 송장 엑셀용 데이터 ───────────────────────────────────────────────
router.get('/alwayz-orders/invoice-excel-data', requireAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const params = [req.user.id];
    let df = '';
    if (from) { params.push(from); df += ` AND SUBSTRING(order_date,1,10) >= $${params.length}`; }
    if (to)   { params.push(to);   df += ` AND SUBSTRING(order_date,1,10) <= $${params.length}`; }
    const { rows } = await pool.query(
      `SELECT * FROM alwayz_orders WHERE user_id=$1 AND tracking_number IS NOT NULL AND tracking_number <> ''${df} ORDER BY order_date`,
      params
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 SA광고 조회 ────────────────────────────────────────────────────────
router.get('/alwayz-sa-ads', requireAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    const params = [req.user.id];
    let df = '';
    if (start) { params.push(start); df += ` AND SUBSTRING(o.order_date,1,10) >= $${params.length}`; }
    if (end)   { params.push(end);   df += ` AND SUBSTRING(o.order_date,1,10) <= $${params.length}`; }
    const { rows } = await pool.query(`
      SELECT DISTINCT SUBSTRING(o.order_date,1,10) AS ad_date, o.product_id,
             (SELECT product_name FROM alwayz_orders x WHERE x.user_id=o.user_id AND x.product_id=o.product_id ORDER BY order_date DESC LIMIT 1) AS product_name
      FROM alwayz_orders o
      WHERE o.user_id=$1${df}
      ORDER BY ad_date DESC, product_name
    `, params);
    const { rows: saved } = await pool.query(
      `SELECT ad_date, product_id, ad_cost FROM alwayz_sa_ads WHERE user_id=$1`, [req.user.id]
    );
    const savedMap = {};
    saved.forEach(s => { savedMap[s.ad_date+'|'+s.product_id] = s.ad_cost; });
    res.json(rows.map(r => ({ ...r, ad_cost: savedMap[r.ad_date+'|'+r.product_id] ?? null })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 SA광고 저장(upsert) ────────────────────────────────────────────
router.post('/alwayz-sa-ads', requireAuth, async (req, res) => {
  const { ad_date, product_id, product_name, ad_cost } = req.body || {};
  if (!ad_date || !product_id) return res.status(400).json({ error: 'ad_date, product_id 필요' });
  try {
    await pool.query(`
      INSERT INTO alwayz_sa_ads (user_id, ad_date, product_id, product_name, ad_cost, updated_at)
      VALUES ($1,$2,$3,$4,$5,NOW())
      ON CONFLICT (user_id, ad_date, product_id) DO UPDATE SET product_name=EXCLUDED.product_name, ad_cost=EXCLUDED.ad_cost, updated_at=NOW()
    `, [req.user.id, ad_date, product_id, product_name||'', parseFloat(ad_cost)||0]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 올팜광고 조회 ───────────────────────────────────────────────────
router.get('/alwayz-olpam-ads', requireAuth, async (req, res) => {
  try {
    const { start, end } = req.query;
    const params = [req.user.id];
    let q = `SELECT ad_date, ad_cost FROM alwayz_olpam_ads WHERE user_id=$1`;
    if (start) { params.push(start); q += ` AND ad_date >= $${params.length}`; }
    if (end)   { params.push(end);   q += ` AND ad_date <= $${params.length}`; }
    q += ' ORDER BY ad_date DESC';
    const { rows } = await pool.query(q, params);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 올팜광고 저장(upsert) ──────────────────────────────────────────
router.post('/alwayz-olpam-ads', requireAuth, async (req, res) => {
  const { ad_date, ad_cost } = req.body || {};
  if (!ad_date) return res.status(400).json({ error: 'ad_date 필요' });
  try {
    await pool.query(`
      INSERT INTO alwayz_olpam_ads (user_id, ad_date, ad_cost, updated_at)
      VALUES ($1,$2,$3,NOW())
      ON CONFLICT (user_id, ad_date) DO UPDATE SET ad_cost=EXCLUDED.ad_cost, updated_at=NOW()
    `, [req.user.id, ad_date, parseFloat(ad_cost)||0]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 수익분석 (결제일 기준, 상품별 집계 + 총계) ─────────────────────────
router.get('/alwayz-profit', requireAuth, async (req, res) => {
  try {
    const { start, end, groupBy = 'day' } = req.query;
    const params = [req.user.id];
    let dateFilter = '';
    if (start) { params.push(start); dateFilter += ` AND SUBSTRING(o.order_date,1,10) >= $${params.length}`; }
    if (end)   { params.push(end);   dateFilter += ` AND SUBSTRING(o.order_date,1,10) <= $${params.length}`; }

    let periodExpr;
    if (groupBy === 'month')     periodExpr = `SUBSTRING(o.order_date,1,7)`;
    else if (groupBy === 'week') periodExpr = `TO_CHAR(TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD'), 'IYYY-"W"IW')`;
    else                         periodExpr = `SUBSTRING(o.order_date,1,10)`;

    const q = `
      WITH order_costs AS (
        SELECT
          o.product_id,
          o.option_name,
          MAX(o.product_name) AS product_name,
          o.quantity,
          o.product_price,
          o.settlement_amount,
          COALESCE((
            SELECT bp.cost
            FROM alwayz_product_mapping pm
            JOIN b2b_products b2bp
              ON b2bp.user_id = pm.user_id AND b2bp.name = pm.b2b_name AND b2bp.unit = pm.b2b_unit
            JOIN b2b_prices bp
              ON bp.user_id = pm.user_id AND bp.b2b_product_id = b2bp.id
             AND (bp.start_date IS NULL OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' AND bp.start_date <= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
             AND (bp.end_date IS NULL OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' AND bp.end_date >= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
            WHERE pm.user_id = o.user_id AND pm.product_id = o.product_id AND pm.option_name = o.option_name
            ORDER BY bp.start_date DESC NULLS LAST
            LIMIT 1
          ), 0) AS unit_cost
        FROM alwayz_orders o
        WHERE o.user_id = $1${dateFilter}
        GROUP BY o.product_id, o.option_name, o.quantity, o.product_price, o.settlement_amount, o.order_date, o.user_id
      )
      SELECT
        product_id,
        option_name,
        MAX(product_name) AS product_name,
        SUM(quantity)::INTEGER                   AS qty,
        SUM(product_price)::NUMERIC(14,2)        AS gross_sales,
        SUM(settlement_amount)::NUMERIC(14,2)    AS settlement,
        SUM(unit_cost * quantity)::NUMERIC(14,2) AS total_cost,
        BOOL_OR(unit_cost > 0)                   AS has_cost
      FROM order_costs
      GROUP BY product_id, option_name
      ORDER BY settlement DESC
    `;
    const { rows } = await pool.query(q, params);

    let tGross=0, tSettle=0, tCost=0, tProfit=0;
    const products = rows.map(r => {
      const gross  = parseFloat(r.gross_sales)||0;
      const settle = parseFloat(r.settlement)||0;
      const cost   = parseFloat(r.total_cost)||0;
      const commission = gross - settle;
      const ad  = 0;
      const tax = -(commission/11) - (ad/11);
      const profit = settle - cost - ad - tax;
      tGross+=gross; tSettle+=settle; tCost+=cost; tProfit+=profit;
      return {
        product_id:   r.product_id,
        product_name: r.product_name,
        option_name:  r.option_name,
        qty:          r.qty,
        gross_sales:  Math.round(gross),
        settlement:   Math.round(settle),
        commission:   Math.round(commission),
        total_cost:   Math.round(cost),
        has_cost:     r.has_cost,
        net_profit:   Math.round(profit),
        margin_rate:  settle>0 ? Math.round(profit/settle*1000)/10 : 0,
      };
    });
    const periodQ = `
      WITH order_costs AS (
        SELECT
          ${periodExpr} AS period_key,
          o.quantity, o.product_price, o.settlement_amount,
          COALESCE((
            SELECT bp.cost FROM alwayz_product_mapping pm
            JOIN b2b_products b2bp ON b2bp.user_id=pm.user_id AND b2bp.name=pm.b2b_name AND b2bp.unit=pm.b2b_unit
            JOIN b2b_prices bp ON bp.user_id=pm.user_id AND bp.b2b_product_id=b2bp.id
             AND (bp.start_date IS NULL OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' AND bp.start_date <= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
             AND (bp.end_date IS NULL OR (o.order_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' AND bp.end_date >= TO_DATE(SUBSTRING(o.order_date,1,10),'YYYY-MM-DD')))
            WHERE pm.user_id=o.user_id AND pm.product_id=o.product_id AND pm.option_name=o.option_name
            ORDER BY bp.start_date DESC NULLS LAST LIMIT 1
          ), 0) AS unit_cost
        FROM alwayz_orders o
        WHERE o.user_id=$1${dateFilter}
      )
      SELECT period_key,
        SUM(product_price)::NUMERIC(14,2)        AS gross_sales,
        SUM(settlement_amount)::NUMERIC(14,2)    AS settlement,
        SUM(unit_cost * quantity)::NUMERIC(14,2) AS total_cost,
        SUM(quantity)::INTEGER                   AS qty
      FROM order_costs
      GROUP BY period_key
      ORDER BY period_key DESC
    `;
    const { rows: periodRows } = await pool.query(periodQ, params);
    const periods = periodRows.map(r => {
      const gross=parseFloat(r.gross_sales)||0, settle=parseFloat(r.settlement)||0, cost=parseFloat(r.total_cost)||0;
      const commission=gross-settle, ad=0, tax=-(commission/11)-(ad/11);
      const profit=settle-cost-ad-tax;
      return { period:r.period_key, qty:r.qty, settlement:Math.round(settle), total_cost:Math.round(cost), net_profit:Math.round(profit), margin_rate:settle>0?Math.round(profit/settle*1000)/10:0 };
    });

    res.json({
      summary: {
        gross_sales:   Math.round(tGross),
        settlement:    Math.round(tSettle),
        total_cost:    Math.round(tCost),
        net_profit:    Math.round(tProfit),
        margin_rate:   tSettle>0 ? Math.round(tProfit/tSettle*1000)/10 : 0,
        product_count: products.length,
        no_cost_count: products.filter(p=>!p.has_cost).length,
      },
      products,
      periods,
    });
  } catch(e) { console.error('[alwayz-profit]', e.message); res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 원가표 조회 (주문서 상품 전체 + 저장된 원가 LEFT JOIN) ────────────
router.get('/alwayz-cost-mapping', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        d.product_id,
        d.option_name,
        MAX(d.product_name) AS product_name,
        MAX(d.order_date)   AS last_order_date,
        COUNT(*)            AS order_count,
        pm.b2b_name,
        pm.b2b_unit
      FROM alwayz_orders d
      LEFT JOIN alwayz_product_mapping pm
        ON pm.user_id = d.user_id AND pm.product_id = d.product_id AND pm.option_name = d.option_name
      WHERE d.user_id = $1
      GROUP BY d.product_id, d.option_name, pm.b2b_name, pm.b2b_unit
      ORDER BY MAX(d.order_date) DESC
    `, [req.user.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 올웨이즈 상품 → B2B 연결 저장(upsert) ───────────────────────────────────
router.post('/alwayz-cost-mapping', requireAuth, async (req, res) => {
  const { product_id, option_name, product_name, b2b_name, b2b_unit } = req.body || {};
  if (!product_id || !b2b_name) return res.status(400).json({ error: 'product_id와 b2b_name 필요' });
  try {
    await pool.query(`
      INSERT INTO alwayz_product_mapping (user_id, product_id, option_name, product_name, b2b_name, b2b_unit, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,NOW())
      ON CONFLICT (user_id, product_id, option_name) DO UPDATE SET
        product_name = EXCLUDED.product_name,
        b2b_name = EXCLUDED.b2b_name,
        b2b_unit = EXCLUDED.b2b_unit,
        updated_at = NOW()
    `, [req.user.id, product_id, option_name||'', product_name||'', b2b_name, b2b_unit||'']);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── [임시 디버그] 도매처 상품 status 무필터 조회 ────────────────────────────────
router.get('/admin/debug-supplier-products', requireRealAdmin, async (req, res) => {
  try {
    const supplierName = req.query.name || '에코앤팜';
    const keyword = req.query.keyword || '참외';
    const { rows } = await pool.query(
      `SELECT * FROM wholesale_suppliers WHERE user_id=$1 AND name=$2 AND api_linked=true`,
      [req.user.id, supplierName]
    );
    if (!rows.length) return res.json({ error: '도매처 없음: '+supplierName });
    const cfg = getSupplierApiConfig(rows[0]);
    if (!cfg || cfg.type !== 'adminplus') return res.json({ error: 'adminplus 아님' });
    const token = await adminplusGetToken(cfg.clientId, cfg.clientSecret);

    let allItems = [], cursor = null, pages = 0;
    do {
      const params = { limit: 500 };
      if (cursor) params.cursor = cursor;
      const data = await adminplusGetProducts(token, params);
      allItems = allItems.concat(data.items || []);
      cursor = data.has_more ? data.next_cursor : null;
      pages++;
    } while (cursor && pages < 50);

    const matched = allItems.filter(p => (p.name||'').includes(keyword));
    const statusDist = {};
    allItems.forEach(p => { statusDist[p.status||'(없음)'] = (statusDist[p.status||'(없음)']||0)+1; });

    res.json({
      supplier: supplierName,
      total_all_status: allItems.length,
      status_distribution: statusDist,
      keyword: keyword,
      matched_count: matched.length,
      matched_samples: matched.slice(0, 15).map(p => ({ name: p.name, status: p.status, stock: p.stock, price: p.price })),
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── 도매처 송장 수집+매칭 ────────────────────────────────────────────────────────
router.post('/orders/collect-invoices', requireAuth, async (req, res) => {
  try {
    const { from, to, dryRun = false } = req.body;
    if (!from || !to) return res.status(400).json({ error: 'from, to 필요 (ordered_at 기간)' });

    // 1. 대상 주문: 결제일 기준, 직접주문 포함 (송장 있는 건도 포함 — 재다운로드 지원)
    const { rows: orders } = await pool.query(
      `SELECT id, order_number, recipient_phone_masked, ordered_supplier_id,
              bundle_number, product_name, option_name, option_id, quantity,
              courier, tracking_number
       FROM orders
       WHERE user_id=$1
         AND order_date IS NOT NULL AND order_date <> ''
         AND SUBSTRING(order_date,1,10) >= $2
         AND SUBSTRING(order_date,1,10) <= $3`,
      [req.user.id, from, to]
    );
    if (!orders.length) return res.json({ matched: 0, unmatched: [], total: 0, message: '대상 주문 없음' });

    // 2. 도매처별 송장 수집 (연동된 전체 도매처)
    const { rows: linkedSuppliers } = await pool.query(
      `SELECT id FROM wholesale_suppliers WHERE user_id=$1 AND api_linked=true AND api_type='adminplus' ORDER BY id`,
      [req.user.id]
    );
    const supplierIds = linkedSuppliers.map(s => s.id);
    const invoiceMap = {};  // supplierId -> invoices[]
    const supplierErrors = {};
    for (const sid of supplierIds) {
      try {
        invoiceMap[sid] = await fetchSupplierInvoices(req.user.id, sid);
      } catch(e) {
        supplierErrors[sid] = e.message;
        invoiceMap[sid] = [];
      }
    }

    // 3. 매칭
    const invoiceCountBySupplier = {};
    for (const sid of supplierIds) invoiceCountBySupplier[sid] = (invoiceMap[sid] || []).length;

    const matched = [];
    const unmatched = [];
    for (const order of orders) {
      // 이미 송장이 채워진 주문 → DB값으로 바로 매칭 성공 (도매처 재조회 불필요)
      if (order.tracking_number && order.tracking_number.trim()) {
        matched.push({
          order_id: order.id,
          order_number: order.order_number,
          bundle_number: order.bundle_number || '',
          product_name: order.product_name || '',
          option_name: order.option_name || '',
          option_id: order.option_id || '',
          quantity: order.quantity || 1,
          match_by: 'already_done',
          shipping_company: order.courier || '',
          tracking_number: order.tracking_number,
        });
        continue;
      }

      const ourPhone = normalizePhone(order.recipient_phone_masked);
      const ourOrderNum = (order.order_number || '').trim();

      // 발주도매처 우선, 없으면 전체 도매처 순서로 검색
      let searchSids;
      if (order.ordered_supplier_id && invoiceMap[order.ordered_supplier_id]) {
        searchSids = [order.ordered_supplier_id, ...supplierIds.filter(s => s !== order.ordered_supplier_id)];
      } else {
        searchSids = supplierIds;
      }

      // 1차: 쿠팡 주문번호 매칭
      let hit = null, hitSid = null;
      if (ourOrderNum) {
        for (const sid of searchSids) {
          const found = (invoiceMap[sid]||[]).find(inv => inv.customer_order_code && inv.customer_order_code.trim() === ourOrderNum);
          if (found) { hit = found; hitSid = sid; break; }
        }
      }

      // 2차: 안심번호 매칭
      if (!hit && ourPhone) {
        for (const sid of searchSids) {
          const found = (invoiceMap[sid]||[]).find(inv => normalizePhone(inv.receiver_phone) === ourPhone);
          if (found) { hit = found; hitSid = sid; break; }
        }
      }

      if (hit) {
        if (!dryRun) {
          await pool.query(
            `UPDATE orders SET courier=$1, tracking_number=$2 WHERE id=$3 AND user_id=$4`,
            [hit.shipping_company, hit.tracking_number, order.id, req.user.id]
          );
        }
        matched.push({
          order_id: order.id,
          order_number: order.order_number,
          bundle_number: order.bundle_number || '',
          product_name: order.product_name || '',
          option_name: order.option_name || '',
          option_id: order.option_id || '',
          quantity: order.quantity || 1,
          match_by: hit.customer_order_code?.trim() === ourOrderNum ? 'order_number' : 'phone',
          shipping_company: hit.shipping_company,
          tracking_number: hit.tracking_number,
        });
      } else {
        const invCount = order.ordered_supplier_id
          ? (invoiceCountBySupplier[order.ordered_supplier_id] || 0)
          : Object.values(invoiceCountBySupplier).reduce((a, b) => a + b, 0);
        const supInvoices = invoiceMap[order.ordered_supplier_id] || [];
        let reason;
        const sidErr = order.ordered_supplier_id ? supplierErrors[order.ordered_supplier_id] : null;
        if (sidErr) {
          const errMsg = sidErr;
          reason = errMsg.includes('API 설정 없음') || errMsg.includes('미연결')
            ? 'API미연동_도매처(수동처리)'
            : 'API오류';
        } else if (invCount === 0) {
          reason = '미발송_또는_송장미등록';
        } else if (!ourPhone || ourPhone.length < 10) {
          reason = '안심번호_소실(14일마스킹_과거건)';
        } else {
          reason = '미발송_송장대기(도매처가_아직_송장미등록)';
        }
        unmatched.push({
          order_id: order.id,
          order_number: order.order_number || '(비어있음)',
          supplier_id: order.ordered_supplier_id,
          our_phone_norm: ourPhone || '(전화없음)',
          has_order_number: !!ourOrderNum,
          supplier_invoice_count: invCount,
          reason,
          supplier_error: (order.ordered_supplier_id ? supplierErrors[order.ordered_supplier_id] : null) || null,
        });
      }
    }

    res.json({
      dryRun: !!dryRun,
      total: orders.length,
      matched: matched.length,
      unmatched_count: unmatched.length,
      matched_list: matched,
      unmatched: unmatched,
      supplier_errors: supplierErrors,
      invoice_count_by_supplier: invoiceCountBySupplier,
    });
  } catch(e) { res.status(500).json({ error: e.message, stack: e.stack }); }
});

module.exports = router;
module.exports.syncSupplierProductsForUser = syncSupplierProductsForUser;
module.exports.fetchSupplierBalancesForUser = fetchSupplierBalancesForUser;
module.exports.maskName      = maskName;
module.exports.maskPhone     = maskPhone;
module.exports.maskAddr      = maskAddr;
module.exports.maskOldOrders = maskOldOrders;
