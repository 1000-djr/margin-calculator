/**
 * crawler.js
 * Playwright 기반 B2B 사이트 가격 수집기.
 * adminplus.co.kr 로그인 후 상품 목록에서 가격을 추출하여 DB에 저장합니다.
 *
 * 환경변수:
 *   ADMINPLUS_URL      - 상품 목록 페이지 URL (기본값 아래 참고)
 *   ADMINPLUS_USERNAME - 로그인 아이디
 *   ADMINPLUS_PASSWORD - 로그인 비밀번호
 */

const { chromium } = require('playwright');
const { pool } = require('./db');

// ─── 사이트별 크롤링 설정 ──────────────────────────────────────────
const SITE_CONFIGS = {
  adminplus: {
    loginUrl: 'https://www.adminplus.co.kr/member/login',
    productUrl: process.env.ADMINPLUS_URL || 'https://www.adminplus.co.kr/product/list',
    usernameEnv: 'ADMINPLUS_USERNAME',
    passwordEnv: 'ADMINPLUS_PASSWORD',
    selectors: {
      usernameInput: 'input[name="id"], input[name="username"], #id, #username',
      passwordInput: 'input[name="pw"], input[name="password"], #pw, #password',
      loginButton:   'button[type="submit"], input[type="submit"], .btn-login',
      // 상품 목록: 실제 사이트 구조에 맞게 수정 필요
      productRows:   '.product-list tr, .list-body tr, table.list tbody tr',
      productName:   'td.name, td:nth-child(2), .product-name',
      productPrice:  'td.price, td:nth-child(4), .price',
      productUnit:   'td.unit, td:nth-child(3), .unit',
      productId:     'td.code, td:nth-child(1), .code',
    },
  },
};

// ─── 로그인 ───────────────────────────────────────────────────────
async function login(page, config) {
  const { loginUrl, usernameEnv, passwordEnv, selectors } = config;
  const username = process.env[usernameEnv];
  const password = process.env[passwordEnv];

  if (!username || !password) {
    throw new Error(`환경변수 ${usernameEnv} 또는 ${passwordEnv} 가 설정되지 않았습니다.`);
  }

  await page.goto(loginUrl, { waitUntil: 'domcontentloaded' });
  await page.fill(selectors.usernameInput, username);
  await page.fill(selectors.passwordInput, password);
  await page.click(selectors.loginButton);
  await page.waitForLoadState('networkidle');

  // 로그인 실패 감지: URL이 로그인 페이지에 그대로면 실패로 판단
  if (page.url().includes('/login')) {
    throw new Error('로그인 실패 — 아이디/비밀번호를 확인하세요.');
  }
  console.log(`[crawler] 로그인 성공: ${page.url()}`);
}

// ─── 상품 가격 수집 ───────────────────────────────────────────────
async function scrapeProducts(page, config) {
  const { productUrl, selectors } = config;
  await page.goto(productUrl, { waitUntil: 'domcontentloaded' });

  const items = [];
  const rows = await page.$$(selectors.productRows);

  for (const row of rows) {
    try {
      const nameEl  = await row.$(selectors.productName);
      const priceEl = await row.$(selectors.productPrice);
      const unitEl  = await row.$(selectors.productUnit);
      const idEl    = await row.$(selectors.productId);

      if (!nameEl || !priceEl) continue;

      const name  = (await nameEl.innerText()).trim();
      const priceRaw = (await priceEl.innerText()).replace(/[^0-9]/g, '');
      const price = parseInt(priceRaw, 10);
      const unit  = unitEl ? (await unitEl.innerText()).trim() : '';
      const externalId = idEl ? (await idEl.innerText()).trim() : name;

      if (!name || isNaN(price)) continue;
      items.push({ name, price, unit, externalId });
    } catch (_) {
      // 파싱 실패한 행은 건너뜀
    }
  }

  return items;
}

// ─── DB 저장 ──────────────────────────────────────────────────────
async function saveToDb(siteId, items) {
  for (const item of items) {
    // products upsert
    const res = await pool.query(
      `INSERT INTO products (site_id, name, unit, external_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (site_id, external_id) DO UPDATE
         SET name = EXCLUDED.name, unit = EXCLUDED.unit
       RETURNING id`,
      [siteId, item.name, item.unit, item.externalId]
    );
    const productId = res.rows[0].id;

    // price_history insert
    await pool.query(
      `INSERT INTO price_history (product_id, price) VALUES ($1, $2)`,
      [productId, item.price]
    );
  }
  console.log(`[crawler] site_id=${siteId} 상품 ${items.length}건 저장 완료`);
}

// ─── 단일 사이트 크롤링 ───────────────────────────────────────────
async function crawlSite(siteRow) {
  const configKey = Object.keys(SITE_CONFIGS).find(k =>
    siteRow.url && siteRow.url.includes(k.replace('adminplus', 'adminplus.co.kr'))
  ) || 'adminplus';

  // DB에 등록된 env 키가 있으면 config에 덮어씀
  const config = { ...SITE_CONFIGS[configKey] };
  if (siteRow.username_env) config.usernameEnv = siteRow.username_env;
  if (siteRow.password_env) config.passwordEnv = siteRow.password_env;
  if (siteRow.login_url)    config.loginUrl     = siteRow.login_url;
  if (siteRow.url)          config.productUrl   = siteRow.url;

  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await login(page, config);
    const items = await scrapeProducts(page, config);
    await saveToDb(siteRow.id, items);
    return { siteId: siteRow.id, count: items.length, error: null };
  } catch (err) {
    console.error(`[crawler] site_id=${siteRow.id} 오류:`, err.message);
    return { siteId: siteRow.id, count: 0, error: err.message };
  } finally {
    await browser.close();
  }
}

// ─── 전체 등록 사이트 크롤링 ──────────────────────────────────────
async function runAll() {
  const { rows } = await pool.query('SELECT * FROM b2b_sites ORDER BY id');
  if (!rows.length) {
    console.log('[crawler] 등록된 B2B 사이트 없음');
    return [];
  }
  const results = [];
  for (const site of rows) {
    const result = await crawlSite(site);
    results.push(result);
  }
  return results;
}

module.exports = { runAll, crawlSite };
