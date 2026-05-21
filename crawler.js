/**
 * crawler.js — adminplus.co.kr 상품 가격 수집기
 *
 * 흐름:
 *   1. 로그인
 *   2. 상품 리스트 페이지 진입
 *   3. 페이지네이션 전체 순회
 *      ├─ 각 상품 카드에서 썸네일 이미지 URL 수집
 *      └─ 카드 클릭 → 팝업 모달 오픈
 *          └─ 모달 테이블 파싱: 제품명 / 재고 / 공급가 / 판매가 / 과세여부 / 배송비
 *   4. DB 저장 (products upsert + price_history insert)
 *
 * 환경변수 (DB에 등록된 b2b_sites 행의 username_env / password_env 키로 읽음):
 *   ADMINPLUS_USERNAME  - 로그인 아이디
 *   ADMINPLUS_PASSWORD  - 로그인 비밀번호
 */

const { chromium } = require('playwright');
const { pool } = require('./db');

// ─── 셀렉터 ────────────────────────────────────────────────────────────────
// ※ 실제 adminplus.co.kr DOM 구조에 따라 조정 필요
const SEL = {
  // 로그인
  loginId:   '#member_id',
  loginPw:   '#member_pw',
  loginBtn:  '.btn_login, button[type="submit"]',

  // 상품 리스트
  productCard:  '.goods_list .item, .product_list .item, .goods-item',
  cardThumbnail: 'img',                   // 카드 내 썸네일 <img>
  cardExternalId: '[data-id], [data-goods-no]', // 카드에 붙은 상품 고유 ID 속성

  // 팝업 모달
  modal:       '.modal, .popup_layer, .layer_popup, #popup',
  modalClose:  '.btn_close, .close, .popup_close, [data-close]',
  modalTable:  'table',                   // 모달 내 첫 번째 테이블
  modalRows:   'tbody tr',               // 테이블 데이터 행

  // 페이지네이션
  nextPage: '.pagination .next:not(.disabled), .paging .next:not(.disabled), a.next',
};

// 모달 테이블 컬럼 순서 (0-based index)
const COL = {
  name:        0,  // 제품명
  stock:       1,  // 재고
  supplyPrice: 2,  // 공급가
  salePrice:   3,  // 판매가
  taxType:     4,  // 과세여부
  shippingFee: 5,  // 배송비
};

// ─── 유틸 ───────────────────────────────────────────────────────────────────
const toInt = (text) => {
  const n = parseInt((text || '').replace(/[^0-9]/g, ''), 10);
  return isNaN(n) ? null : n;
};

const getText = async (el, selector) => {
  const child = await el.$(selector);
  return child ? (await child.innerText()).trim() : '';
};

// ─── 로그인 ─────────────────────────────────────────────────────────────────
async function login(page, { loginUrl, usernameEnv, passwordEnv }) {
  const username = process.env[usernameEnv];
  const password = process.env[passwordEnv];

  if (!username || !password) {
    throw new Error(
      `환경변수 ${usernameEnv} 또는 ${passwordEnv} 가 설정되지 않았습니다.`
    );
  }

  await page.goto(loginUrl, { waitUntil: 'domcontentloaded' });
  await page.fill(SEL.loginId, username);
  await page.fill(SEL.loginPw, password);
  await page.click(SEL.loginBtn);
  await page.waitForLoadState('networkidle');

  if (page.url().includes('login')) {
    throw new Error('로그인 실패 — 아이디/비밀번호를 확인하세요.');
  }
  console.log(`[crawler] 로그인 성공: ${page.url()}`);
}

// ─── 모달에서 행 데이터 파싱 ────────────────────────────────────────────────
async function parseModal(page) {
  // 모달이 나타날 때까지 대기 (최대 5초)
  const modal = await page.waitForSelector(SEL.modal, { timeout: 5000 }).catch(() => null);
  if (!modal) {
    console.warn('[crawler] 모달을 찾지 못했습니다.');
    return [];
  }

  const table = await modal.$(SEL.modalTable);
  if (!table) {
    console.warn('[crawler] 모달 내 테이블을 찾지 못했습니다.');
    return [];
  }

  const rows = await table.$$(SEL.modalRows);
  const items = [];

  for (const row of rows) {
    const cells = await row.$$('td');
    if (cells.length <= COL.supplyPrice) continue;

    const name        = (await cells[COL.name].innerText()).trim();
    const stock       = toInt(await cells[COL.stock].innerText());
    const supplyPrice = toInt(await cells[COL.supplyPrice].innerText());
    const salePrice   = toInt(await cells[COL.salePrice].innerText());
    const taxType     = (await cells[COL.taxType].innerText()).trim() || null;
    const shippingFee = toInt(await cells[COL.shippingFee].innerText());

    if (!name || supplyPrice === null) continue;

    items.push({ name, stock, supplyPrice, salePrice, taxType, shippingFee });
  }

  return items;
}

// ─── 모달 닫기 ──────────────────────────────────────────────────────────────
async function closeModal(page) {
  const closeBtn = await page.$(SEL.modalClose);
  if (closeBtn) {
    await closeBtn.click();
  } else {
    await page.keyboard.press('Escape');
  }
  // 모달이 사라질 때까지 대기
  await page.waitForSelector(SEL.modal, { state: 'hidden', timeout: 3000 }).catch(() => {});
}

// ─── 한 페이지의 카드 전체 수집 ─────────────────────────────────────────────
async function scrapeCurrentPage(page) {
  const cards = await page.$$(SEL.productCard);
  console.log(`[crawler] 카드 ${cards.length}개 발견`);

  const results = [];

  for (let i = 0; i < cards.length; i++) {
    try {
      // 카드를 다시 선택 (DOM이 재렌더링될 수 있으므로)
      const freshCards = await page.$$(SEL.productCard);
      const card = freshCards[i];
      if (!card) continue;

      // 썸네일 이미지 URL
      const imgEl = await card.$(SEL.cardThumbnail);
      const imageUrl = imgEl
        ? (await imgEl.getAttribute('src') || await imgEl.getAttribute('data-src') || null)
        : null;

      // 카드 고유 ID (data 속성 → 없으면 인덱스로 대체)
      const externalId =
        (await card.getAttribute('data-id')) ||
        (await card.getAttribute('data-goods-no')) ||
        String(i);

      // 카드 클릭 → 모달 오픈
      await card.click();

      // 모달 파싱
      const modalItems = await parseModal(page);

      for (const item of modalItems) {
        results.push({
          externalId,
          imageUrl,
          ...item,
        });
      }

      // 모달 닫기
      await closeModal(page);

      // 다음 카드 전에 짧은 대기 (서버 부하 방지)
      await page.waitForTimeout(300);
    } catch (err) {
      console.warn(`[crawler] 카드 ${i} 처리 중 오류:`, err.message);
      await closeModal(page).catch(() => {});
    }
  }

  return results;
}

// ─── 상품 리스트 전체 수집 (페이지네이션 포함) ──────────────────────────────
async function scrapeAllProducts(page, productUrl) {
  await page.goto(productUrl, { waitUntil: 'domcontentloaded' });

  const allItems = [];
  let pageNum = 1;

  while (true) {
    console.log(`[crawler] 페이지 ${pageNum} 수집 중…`);
    const items = await scrapeCurrentPage(page);
    allItems.push(...items);

    // 다음 페이지 버튼 확인
    const nextBtn = await page.$(SEL.nextPage);
    if (!nextBtn) break;

    await nextBtn.click();
    await page.waitForLoadState('domcontentloaded');
    pageNum++;
  }

  console.log(`[crawler] 전체 ${allItems.length}건 수집 완료`);
  return allItems;
}

// ─── DB 저장 ────────────────────────────────────────────────────────────────
async function saveToDb(siteId, items) {
  let saved = 0;

  for (const item of items) {
    try {
      // products upsert
      const res = await pool.query(
        `INSERT INTO products (site_id, name, unit, external_id, image_url)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (site_id, external_id) DO UPDATE
           SET name      = EXCLUDED.name,
               image_url = EXCLUDED.image_url
         RETURNING id`,
        [siteId, item.name, item.unit || null, item.externalId, item.imageUrl]
      );
      const productId = res.rows[0].id;

      // price_history insert
      await pool.query(
        `INSERT INTO price_history
           (product_id, supply_price, sale_price, stock, tax_type, shipping_fee)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          productId,
          item.supplyPrice,
          item.salePrice,
          item.stock,
          item.taxType,
          item.shippingFee,
        ]
      );
      saved++;
    } catch (err) {
      console.warn(`[crawler] DB 저장 실패 (${item.name}):`, err.message);
    }
  }

  console.log(`[crawler] site_id=${siteId} — ${saved}/${items.length}건 저장 완료`);
  return saved;
}

// ─── 단일 사이트 크롤링 ─────────────────────────────────────────────────────
async function crawlSite(siteRow) {
  const config = {
    loginUrl:    siteRow.login_url || 'https://www.adminplus.co.kr/member/login',
    productUrl:  siteRow.url,
    usernameEnv: siteRow.username_env || 'ADMINPLUS_USERNAME',
    passwordEnv: siteRow.password_env || 'ADMINPLUS_PASSWORD',
  };

  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ' +
        'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    });
    const page = await context.newPage();

    await login(page, config);
    const items = await scrapeAllProducts(page, config.productUrl);
    const saved = await saveToDb(siteRow.id, items);

    return { siteId: siteRow.id, count: saved, error: null };
  } catch (err) {
    console.error(`[crawler] site_id=${siteRow.id} 오류:`, err.message);
    return { siteId: siteRow.id, count: 0, error: err.message };
  } finally {
    await browser.close();
  }
}

// ─── 전체 등록 사이트 크롤링 ─────────────────────────────────────────────────
async function runAll() {
  const { rows } = await pool.query('SELECT * FROM b2b_sites ORDER BY id');
  if (!rows.length) {
    console.log('[crawler] 등록된 B2B 사이트 없음');
    return [];
  }

  const results = [];
  for (const site of rows) {
    results.push(await crawlSite(site));
  }
  return results;
}

module.exports = { runAll, crawlSite };
