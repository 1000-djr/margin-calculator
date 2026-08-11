const { Pool } = require('pg');

const pool = new Pool({
  connectionString:     process.env.DATABASE_URL,
  ssl:                  process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max:                  10,
  idleTimeoutMillis:    30000,
  connectionTimeoutMillis: 5000,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      google_id  VARCHAR(100) UNIQUE NOT NULL,
      email      VARCHAR(200),
      name       VARCHAR(200),
      picture    TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_data (
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      key        VARCHAR(50) NOT NULL,
      value      JSONB,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, key)
    );

    CREATE TABLE IF NOT EXISTS b2b_sites (
      id           SERIAL PRIMARY KEY,
      name         VARCHAR(100) NOT NULL,
      url          VARCHAR(500) NOT NULL,
      login_url    VARCHAR(500),
      username_env VARCHAR(100),
      password_env VARCHAR(100),
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS products (
      id          SERIAL PRIMARY KEY,
      site_id     INTEGER REFERENCES b2b_sites(id) ON DELETE CASCADE,
      name        VARCHAR(200) NOT NULL,
      unit        VARCHAR(50),
      external_id VARCHAR(200),
      image_url   TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (site_id, external_id)
    );

    CREATE TABLE IF NOT EXISTS price_history (
      id           SERIAL PRIMARY KEY,
      product_id   INTEGER REFERENCES products(id) ON DELETE CASCADE,
      supply_price INTEGER,
      sale_price   INTEGER,
      stock        INTEGER,
      tax_type     VARCHAR(20),
      shipping_fee INTEGER,
      crawled_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // 기존 DB 마이그레이션: 컬럼이 없으면 추가
  await pool.query(`
    ALTER TABLE products      ADD COLUMN IF NOT EXISTS image_url    TEXT;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS supply_price INTEGER;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS sale_price   INTEGER;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS stock        INTEGER;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS tax_type     VARCHAR(20);
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS shipping_fee INTEGER;
  `);

  // 신규 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id                       SERIAL PRIMARY KEY,
      user_id                  INTEGER REFERENCES users(id) ON DELETE CASCADE,
      order_number             VARCHAR(100) NOT NULL,
      bundle_number            VARCHAR(100),
      order_date               VARCHAR(50),
      product_name             TEXT,
      option_name              TEXT,
      display_name             TEXT,
      display_product_id       VARCHAR(100),
      option_id                VARCHAR(100),
      payment_amount           INTEGER DEFAULT 0,
      shipping_fee             INTEGER DEFAULT 0,
      quantity                 INTEGER DEFAULT 1,
      unit_price               INTEGER DEFAULT 0,
      courier                  VARCHAR(100),
      tracking_number          VARCHAR(100),
      shipped_date             VARCHAR(50),
      delivered_date           VARCHAR(50),
      confirmed_date           VARCHAR(50),
      payment_location         VARCHAR(100),
      delivery_type            VARCHAR(100),
      buyer_masked             VARCHAR(100),
      recipient_name_masked    VARCHAR(100),
      recipient_phone_masked   VARCHAR(50),
      recipient_address_masked TEXT,
      is_excluded              BOOLEAN DEFAULT FALSE,
      created_at               TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, order_number)
    );

    CREATE TABLE IF NOT EXISTS alwayz_orders (
      id                  SERIAL PRIMARY KEY,
      user_id             INTEGER REFERENCES users(id) ON DELETE CASCADE,
      order_id            VARCHAR(100) NOT NULL,
      product_id          VARCHAR(100),
      bundle_id           VARCHAR(200),
      seller_product_code VARCHAR(200),
      product_name        TEXT,
      option_name         TEXT,
      quantity            INTEGER DEFAULT 1,
      product_price       NUMERIC(14,2) DEFAULT 0,
      delivery_fee        NUMERIC(14,2) DEFAULT 0,
      extra_support       NUMERIC(14,2) DEFAULT 0,
      coupon_alwayz       NUMERIC(14,2) DEFAULT 0,
      coupon_seller       NUMERIC(14,2) DEFAULT 0,
      coupon_total        NUMERIC(14,2) DEFAULT 0,
      settlement_amount   NUMERIC(14,2) DEFAULT 0,
      address             TEXT,
      zipcode             VARCHAR(20),
      entrance_password   VARCHAR(100),
      receive_method      VARCHAR(100),
      recipient           VARCHAR(100),
      recipient_phone     VARCHAR(50),
      order_date          VARCHAR(30),
      courier             VARCHAR(50),
      tracking_number     VARCHAR(100),
      unique_code         VARCHAR(200),
      ordered_at          TIMESTAMPTZ,
      ordered_supplier_id INTEGER,
      created_at          TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, order_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS alwayz_cost_mapping (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      product_id   VARCHAR(100) NOT NULL,
      option_name  TEXT NOT NULL DEFAULT '',
      product_name TEXT,
      cost         NUMERIC(14,2) DEFAULT 0,
      tax_type     VARCHAR(20) DEFAULT 'exempt',
      updated_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, product_id, option_name)
    );

    CREATE TABLE IF NOT EXISTS alwayz_product_mapping (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      product_id   VARCHAR(100) NOT NULL,
      option_name  TEXT NOT NULL DEFAULT '',
      product_name TEXT,
      b2b_name     TEXT NOT NULL,
      b2b_unit     TEXT NOT NULL DEFAULT '',
      updated_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, product_id, option_name)
    );

    CREATE TABLE IF NOT EXISTS alwayz_sa_ads (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      ad_date      VARCHAR(10) NOT NULL,
      product_id   VARCHAR(100) NOT NULL,
      product_name TEXT,
      ad_cost      NUMERIC(14,2) DEFAULT 0,
      updated_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, ad_date, product_id)
    );

    CREATE TABLE IF NOT EXISTS alwayz_olpam_ads (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      ad_date    VARCHAR(10) NOT NULL,
      ad_cost    NUMERIC(14,2) DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, ad_date)
    );

    CREATE TABLE IF NOT EXISTS alwayz_order_mappings (
      id                    SERIAL PRIMARY KEY,
      user_id               INTEGER REFERENCES users(id) ON DELETE CASCADE,
      product_id            VARCHAR(100) NOT NULL,
      option_name           TEXT NOT NULL DEFAULT '',
      registered_name       TEXT,
      supplier_id           INTEGER REFERENCES wholesale_suppliers(id) ON DELETE SET NULL,
      supplier_product_name TEXT,
      supplier_option_name  TEXT DEFAULT '',
      created_at            TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, product_id, option_name)
    );

    CREATE TABLE IF NOT EXISTS ad_reports (
      id               SERIAL PRIMARY KEY,
      user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
      report_date      VARCHAR(50),
      campaign_id      VARCHAR(100),
      campaign_name    TEXT,
      ad_group         TEXT,
      product_name     TEXT,
      option_id        VARCHAR(100),
      keyword          TEXT DEFAULT '',
      impressions      INTEGER DEFAULT 0,
      clicks           INTEGER DEFAULT 0,
      ad_cost          NUMERIC(12,2) DEFAULT 0,
      actual_ad_cost   NUMERIC(12,2) DEFAULT 0,
      orders_1d        INTEGER DEFAULT 0,
      quantity_1d      INTEGER DEFAULT 0,
      revenue_1d       NUMERIC(14,2) DEFAULT 0,
      orders_14d       INTEGER DEFAULT 0,
      quantity_14d     INTEGER DEFAULT 0,
      revenue_14d      NUMERIC(14,2) DEFAULT 0,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, report_date, option_id, keyword, ad_placement)
    );

    CREATE TABLE IF NOT EXISTS coupons (
      id              SERIAL PRIMARY KEY,
      user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
      coupon_id       BIGINT,
      name            TEXT NOT NULL,
      discount_amount NUMERIC(12,2) DEFAULT 0,
      start_at        TIMESTAMPTZ,
      end_at          TIMESTAMPTZ,
      option_ids      JSONB DEFAULT '[]',
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS fixed_discounts (
      id              SERIAL PRIMARY KEY,
      user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
      option_id       VARCHAR(100) NOT NULL,
      discount_amount NUMERIC(12,2) NOT NULL,
      start_date      TIMESTAMPTZ NOT NULL,
      end_date        TIMESTAMPTZ,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS fixed_discounts_unique
      ON fixed_discounts(user_id, option_id, start_date);

    CREATE TABLE IF NOT EXISTS shortcuts (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name       TEXT NOT NULL,
      url        TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cost_mapping (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      option_id    VARCHAR(100) NOT NULL,
      product_name TEXT,
      supplier     TEXT,
      cost         NUMERIC(12,2) DEFAULT 0,
      tax_type     VARCHAR(20) DEFAULT 'exempt',
      applied_date VARCHAR(20),
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, option_id)
    );

    CREATE TABLE IF NOT EXISTS ad_product_mapping (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      ad_option_id VARCHAR(200) NOT NULL,
      product_id   VARCHAR(200),
      product_name TEXT,
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, ad_option_id)
    );

    CREATE TABLE IF NOT EXISTS b2b_products (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name       VARCHAR(200) NOT NULL,
      unit       VARCHAR(50)  NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, name, unit)
    );

    CREATE TABLE IF NOT EXISTS b2b_suppliers (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name       VARCHAR(100) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, name)
    );

    CREATE TABLE IF NOT EXISTS b2b_prices (
      id               SERIAL PRIMARY KEY,
      user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
      b2b_product_id   INTEGER REFERENCES b2b_products(id) ON DELETE CASCADE,
      supplier_id      INTEGER REFERENCES b2b_suppliers(id) ON DELETE CASCADE,
      cost             NUMERIC(12,2) NOT NULL,
      start_date       DATE NOT NULL,
      end_date         DATE,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, b2b_product_id, supplier_id, start_date)
    );
  `);

  // ad_reports 마이그레이션: 원본 전체 데이터 저장 컬럼 추가
  // NOTE: CREATE TABLE ad_reports 이후에 실행해야 신규 DB에서도 정상 동작
  try {
    await pool.query(`
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS raw_data JSONB;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS billing_type   TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS sales_type     TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS ad_type        TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS ad_placement   TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS click_rate     TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS conv_product   TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS conv_option_id TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS direct_orders_1d   INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS indirect_orders_1d INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS direct_qty_1d      INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS indirect_qty_1d    INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS direct_rev_1d      NUMERIC(14,2);
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS indirect_rev_1d    NUMERIC(14,2);
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS direct_orders_14d   INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS indirect_orders_14d INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS direct_qty_14d      INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS indirect_qty_14d    INTEGER;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS direct_rev_14d      NUMERIC(14,2);
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS indirect_rev_14d    NUMERIC(14,2);
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS roas_total_1d       TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS roas_direct_1d      TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS roas_indirect_1d    TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS roas_total_14d      TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS roas_direct_14d     TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS roas_indirect_14d   TEXT;
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS campaign_start      VARCHAR(50);
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS campaign_end        VARCHAR(50);
      ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS note               TEXT;
    `);
  } catch(e) { console.warn('[db] ad_reports 마이그레이션 스킵:', e.message); }

  // coupons 테이블 마이그레이션 (기존 테이블에 신규 컬럼 추가)
  await pool.query(`
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS coupon_id       BIGINT;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS discount_amount NUMERIC(12,2) DEFAULT 0;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS start_at        TIMESTAMPTZ;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS end_at          TIMESTAMPTZ;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS option_ids      JSONB DEFAULT '[]';
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS coupon_type     VARCHAR(20) DEFAULT 'instant';
    UPDATE coupons SET coupon_type = 'instant' WHERE coupon_type IS NULL;
  `);

  await pool.query(`
    ALTER TABLE b2b_prices ADD COLUMN IF NOT EXISTS start_date      DATE;
    ALTER TABLE b2b_prices ADD COLUMN IF NOT EXISTS end_date        DATE;
    ALTER TABLE orders     ADD COLUMN IF NOT EXISTS is_excluded      BOOLEAN DEFAULT FALSE;
    ALTER TABLE orders     ADD COLUMN IF NOT EXISTS exclusion_type   VARCHAR(20) DEFAULT 'normal';
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_name_mapping (
      id                SERIAL PRIMARY KEY,
      user_id           INTEGER REFERENCES users(id) ON DELETE CASCADE,
      registered_name   TEXT NOT NULL,
      option_name       TEXT NOT NULL DEFAULT '',
      b2b_name          TEXT NOT NULL,
      b2b_unit          TEXT NOT NULL DEFAULT '',
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, registered_name, option_name)
    );
  `);

  await pool.query(`
    ALTER TABLE product_name_mapping ADD COLUMN IF NOT EXISTS option_name TEXT NOT NULL DEFAULT '';
    ALTER TABLE product_name_mapping ADD COLUMN IF NOT EXISTS b2b_unit    TEXT NOT NULL DEFAULT '';
    ALTER TABLE product_name_mapping ADD COLUMN IF NOT EXISTS option_id   VARCHAR(100) DEFAULT NULL;
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_pnm_option_id
      ON product_name_mapping(user_id, option_id)
      WHERE option_id IS NOT NULL;
  `);
  // UNIQUE 제약 마이그레이션: (user_id, registered_name) → (user_id, registered_name, option_name)
  await pool.query(`
    DO $$
    DECLARE
      cname TEXT;
    BEGIN
      SELECT conname INTO cname
        FROM pg_constraint
        WHERE conrelid = 'product_name_mapping'::regclass
          AND contype = 'u'
          AND array_length(conkey, 1) = 2;
      IF cname IS NOT NULL THEN
        EXECUTE 'ALTER TABLE product_name_mapping DROP CONSTRAINT ' || quote_ident(cname);
        ALTER TABLE product_name_mapping
          ADD CONSTRAINT product_name_mapping_user_registered_option_unique
          UNIQUE (user_id, registered_name, option_name);
      END IF;
    END$$;
  `);
  // PNM: option_id 포함 UNIQUE 인덱스로 교체
  // 동일 상품명+옵션명이라도 option_id가 다르면 별도 매칭 공존 허용
  try { await pool.query(`ALTER TABLE product_name_mapping DROP CONSTRAINT IF EXISTS product_name_mapping_user_id_registered_name_option_name_key`); } catch(e) { /* 없으면 무시 */ }
  try { await pool.query(`ALTER TABLE product_name_mapping DROP CONSTRAINT IF EXISTS product_name_mapping_user_registered_option_unique`); } catch(e) { /* 없으면 무시 */ }
  try { await pool.query(`DROP INDEX IF EXISTS pnm_unique_idx`); } catch(e) { /* 없으면 무시 */ }
  try { await pool.query(`DROP INDEX IF EXISTS idx_pnm_option_id`); } catch(e) { /* 없으면 무시 */ }
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS pnm_unique_idx
      ON product_name_mapping (user_id, registered_name, option_name, COALESCE(option_id,''))
  `);

  // users 테이블 마이그레이션: status, is_admin, expires_at 컬럼 추가
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS status                VARCHAR(20)  DEFAULT 'pending';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin              BOOLEAN      DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS expires_at            TIMESTAMPTZ  DEFAULT NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS discount_mode         VARCHAR(20)  DEFAULT 'coupon';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_sync_at          TIMESTAMPTZ  DEFAULT NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS returns_last_sync_at  TIMESTAMPTZ  DEFAULT NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS cancel_last_sync_at   TIMESTAMPTZ  DEFAULT NULL;
  `);

  // ADMIN_EMAIL 환경변수로 지정된 유저를 자동으로 active + admin 처리
  if (process.env.ADMIN_EMAIL) {
    await pool.query(`
      UPDATE users
         SET status   = 'active',
             is_admin = TRUE
       WHERE email = $1
    `, [process.env.ADMIN_EMAIL]);
  }

  // ad_reports UNIQUE 제약 마이그레이션:
  // NULL=NULL 비교 문제 해결: 기존 UNIQUE 제약 모두 삭제 후 표현식 인덱스로 교체
  await pool.query(`
    DO $$
    DECLARE
      cname TEXT;
    BEGIN
      -- 기존 UNIQUE 제약 (4컬럼, 5컬럼 모두) 드롭
      FOR cname IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'ad_reports'::regclass
          AND contype = 'u'
      LOOP
        EXECUTE 'ALTER TABLE ad_reports DROP CONSTRAINT ' || quote_ident(cname);
      END LOOP;
    END$$;
  `);
  // 표현식 인덱스로 재생성: campaign_id 추가 + COALESCE로 NULL → '' 처리
  try {
    await pool.query(`DROP INDEX IF EXISTS ad_reports_unique`);
    await pool.query(`
      CREATE UNIQUE INDEX ad_reports_unique
      ON ad_reports(user_id, report_date, campaign_id, option_id,
                    COALESCE(keyword,''), COALESCE(ad_placement,''))
    `);
  } catch(e) { console.warn('[db] ad_reports_unique 인덱스 스킵:', e.message); }

  // ad_placement 백필: raw_data->>'광고 노출 지면' 단일 컬럼으로 NULL 행 업데이트
  const { rowCount: backfilled } = await pool.query(`
    UPDATE ad_reports
    SET ad_placement = raw_data->>'광고 노출 지면'
    WHERE ad_placement IS NULL
      AND raw_data IS NOT NULL
      AND raw_data->>'광고 노출 지면' IS NOT NULL
  `);
  if (backfilled > 0) {
    console.log(`[db] ad_placement 백필 완료: ${backfilled}행 업데이트`);
  }

  // orders 발주 조정 컬럼
  await pool.query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS override_cost_price INTEGER;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS override_cost_note  VARCHAR(500);
  `);

  // 반품 관리 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS returns (
      id                       SERIAL PRIMARY KEY,
      user_id                  INTEGER REFERENCES users(id) ON DELETE CASCADE,
      received_at              VARCHAR(50),
      receipt_number           VARCHAR(100) NOT NULL,
      delivery_status          VARCHAR(100),
      return_status            VARCHAR(100),
      warehousing_status       VARCHAR(100),
      warehousing_method       VARCHAR(100),
      warehousing_tracking     VARCHAR(200),
      product_name             TEXT,
      option_name              TEXT,
      quantity                 INTEGER DEFAULT 1,
      return_reason            TEXT,
      return_shipping_fee      INTEGER DEFAULT 0,
      shipping_fee_burden      VARCHAR(100),
      refund_amount            INTEGER DEFAULT 0,
      recipient_masked         VARCHAR(100),
      phone_masked             VARCHAR(50),
      return_address_masked    TEXT,
      collection_address_masked TEXT,
      order_number             VARCHAR(100),
      expected_ship_date       VARCHAR(50),
      warehousing_complete_date VARCHAR(50),
      return_complete_date     VARCHAR(50),
      receipt_channel          VARCHAR(100),
      option_id                VARCHAR(100),
      return_cost              NUMERIC(12,2) DEFAULT 0,
      return_type              VARCHAR(20)  DEFAULT 'other',
      process_memo             TEXT,
      raw_data                 JSONB,
      created_at               TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, receipt_number)
    );
  `);

  // returns record_type (반품 / 출고중지) — CREATE TABLE 이후에 실행해야 신규 DB에서도 정상 동작
  await pool.query(`
    ALTER TABLE returns ADD COLUMN IF NOT EXISTS record_type VARCHAR(20) DEFAULT 'return';
  `);

  // 플랫폼 확장 1단계: platform 컬럼 추가 + coupang 백필
  // NOTE: 향후 다중플랫폼 시 UNIQUE(user_id, order_number) → UNIQUE(user_id, platform, order_number) 마이그레이션 검토 필요
  await pool.query(`
    ALTER TABLE orders     ADD COLUMN IF NOT EXISTS platform VARCHAR(30) DEFAULT 'coupang';
    ALTER TABLE ad_reports ADD COLUMN IF NOT EXISTS platform VARCHAR(30) DEFAULT 'coupang';
    ALTER TABLE coupons    ADD COLUMN IF NOT EXISTS platform VARCHAR(30) DEFAULT 'coupang';
    ALTER TABLE returns    ADD COLUMN IF NOT EXISTS platform VARCHAR(30) DEFAULT 'coupang';
    UPDATE orders     SET platform = 'coupang' WHERE platform IS NULL;
    UPDATE ad_reports SET platform = 'coupang' WHERE platform IS NULL;
    UPDATE coupons    SET platform = 'coupang' WHERE platform IS NULL;
    UPDATE returns    SET platform = 'coupang' WHERE platform IS NULL;
  `);

  // 가구매 비용 관리
  await pool.query(`
    CREATE TABLE IF NOT EXISTS fake_purchase_vendors (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      vendor_name  VARCHAR(200) NOT NULL,
      method       VARCHAR(20)  NOT NULL DEFAULT '빈박스',
      review_type  VARCHAR(20)  NOT NULL DEFAULT '별점',
      delivery_fee NUMERIC(12,2) DEFAULT 0,
      process_fee  NUMERIC(12,2) DEFAULT 0,
      tax_rate     NUMERIC(5,2)  DEFAULT 0,
      product_cost NUMERIC(12,2) DEFAULT 0,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS fake_purchase_records (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      vendor_id    INTEGER REFERENCES fake_purchase_vendors(id) ON DELETE CASCADE,
      proceed_date VARCHAR(20) NOT NULL,
      order_ids    JSONB DEFAULT '[]',
      total_cost   NUMERIC(14,2) DEFAULT 0,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // fake_purchase_vendors 부가세 유형 컬럼 추가
  await pool.query(`
    ALTER TABLE fake_purchase_vendors ADD COLUMN IF NOT EXISTS process_fee_vat_type  VARCHAR(20) DEFAULT '별도';
    ALTER TABLE fake_purchase_vendors ADD COLUMN IF NOT EXISTS product_tax_type      VARCHAR(20) DEFAULT '면세';
    ALTER TABLE fake_purchase_vendors ADD COLUMN IF NOT EXISTS delivery_fee_vat_type VARCHAR(20) DEFAULT '별도';
  `);

  // fake_purchase_records 과세유형 컬럼 추가
  await pool.query(`
    ALTER TABLE fake_purchase_records ADD COLUMN IF NOT EXISTS tax_type VARCHAR(20) DEFAULT '면세';
  `);

  // 쿠팡 Open API 키 저장 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS coupang_api_keys (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
      vendor_id  VARCHAR(50)  NOT NULL,
      access_key VARCHAR(100) NOT NULL,
      secret_key TEXT         NOT NULL,
      is_active  BOOLEAN      DEFAULT TRUE,
      created_at TIMESTAMPTZ  DEFAULT NOW(),
      updated_at TIMESTAMPTZ  DEFAULT NOW()
    );
  `);

  // 도매처 관리 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wholesale_suppliers (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name       VARCHAR(200) NOT NULL,
      url        TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // 도매처 API 연동 컬럼 (마이그레이션)
  try {
    await pool.query(`ALTER TABLE wholesale_suppliers ADD COLUMN IF NOT EXISTS api_type TEXT`);
    await pool.query(`ALTER TABLE wholesale_suppliers ADD COLUMN IF NOT EXISTS api_client_id TEXT`);
    await pool.query(`ALTER TABLE wholesale_suppliers ADD COLUMN IF NOT EXISTS api_client_secret_enc TEXT`);
    await pool.query(`ALTER TABLE wholesale_suppliers ADD COLUMN IF NOT EXISTS api_linked BOOLEAN DEFAULT FALSE`);
  } catch(e) { console.warn('[db] wholesale_suppliers API 컬럼 추가 실패:', e.message); }
  // 발주 양식 키 (마이그레이션)
  try {
    await pool.query(`ALTER TABLE wholesale_suppliers ADD COLUMN IF NOT EXISTS form_key TEXT`);
  } catch(e) { console.warn('[db] wholesale_suppliers form_key 컬럼 추가 실패:', e.message); }

  // 도매처 상품 캐시 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS supplier_products (
      id               SERIAL PRIMARY KEY,
      user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
      supplier_id      INTEGER REFERENCES wholesale_suppliers(id) ON DELETE CASCADE,
      product_code     TEXT,
      name             TEXT,
      price            NUMERIC(12,2),
      taxable          TEXT,
      image            TEXT,
      stock            TEXT,
      delivery_policy  JSONB,
      order_cutoff_time TEXT,
      unit             TEXT,
      synced_at        TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, supplier_id, product_code)
    );
  `);
  try {
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sp_user_name ON supplier_products(user_id, name)`);
  } catch(e) { console.warn('[db] idx_sp_user_name 생성 실패:', e.message); }

  // 도매처 상품 가격 변동 이력
  await pool.query(`
    CREATE TABLE IF NOT EXISTS supplier_price_history (
      id           SERIAL PRIMARY KEY,
      user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
      supplier_id  INTEGER REFERENCES wholesale_suppliers(id) ON DELETE CASCADE,
      product_code TEXT,
      name         TEXT,
      old_price    NUMERIC(12,2),
      new_price    NUMERIC(12,2),
      changed_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  try {
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sph_user ON supplier_price_history(user_id, changed_at DESC)`);
  } catch(e) { console.warn('[db] idx_sph_user 생성 실패:', e.message); }

  // 도매처 예치금/적립금 잔액 캐시
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS supplier_balances (
        id               SERIAL PRIMARY KEY,
        user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
        supplier_id      INTEGER REFERENCES wholesale_suppliers(id) ON DELETE CASCADE,
        deposit_balance  NUMERIC(14,2),
        point_balance    NUMERIC(14,2),
        fetched_at       TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, supplier_id)
      );
    `);
  } catch(e) { console.warn('[db] supplier_balances 생성 실패:', e.message); }

  // 발주 매칭 테이블 (쿠팡 옵션 → 도매처 + 도매처 상품명)
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS order_mappings (
        id                   SERIAL PRIMARY KEY,
        user_id              INTEGER REFERENCES users(id) ON DELETE CASCADE,
        option_id            VARCHAR(100),
        registered_name      TEXT,
        option_name          TEXT DEFAULT '',
        supplier_id          INTEGER REFERENCES wholesale_suppliers(id) ON DELETE SET NULL,
        supplier_product_name TEXT,
        supplier_option_name TEXT DEFAULT '',
        created_at           TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, option_id)
      );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_om_user ON order_mappings(user_id)`);
  } catch(e) { console.warn('[db] order_mappings 생성 실패:', e.message); }

  // 트래픽 슬롯 관리 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS traffic_slots (
      id             SERIAL PRIMARY KEY,
      user_id        INTEGER REFERENCES users(id) ON DELETE CASCADE,
      vendor_name    VARCHAR(200) NOT NULL,
      option_id      VARCHAR(100) NOT NULL,
      slot_count     INTEGER NOT NULL DEFAULT 1,
      cost_per_slot  NUMERIC(12,2) NOT NULL DEFAULT 0,
      vat_included   BOOLEAN NOT NULL DEFAULT FALSE,
      start_date     TIMESTAMPTZ NOT NULL,
      end_date       TIMESTAMPTZ NOT NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // fixed_discounts: DATE → TIMESTAMPTZ 마이그레이션
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'fixed_discounts'
          AND column_name = 'start_date'
          AND data_type = 'date'
      ) THEN
        ALTER TABLE fixed_discounts ALTER COLUMN start_date TYPE TIMESTAMPTZ USING start_date::TIMESTAMPTZ;
        ALTER TABLE fixed_discounts ALTER COLUMN end_date   TYPE TIMESTAMPTZ USING end_date::TIMESTAMPTZ;
      END IF;
    END $$;
  `);

  // 상시할인가 타입 구분: discount_type 컬럼 추가 + UNIQUE 인덱스를 타입 포함으로 교체
  await pool.query(`
    ALTER TABLE fixed_discounts ADD COLUMN IF NOT EXISTS discount_type VARCHAR(20) DEFAULT 'instant';
    UPDATE fixed_discounts SET discount_type = 'instant' WHERE discount_type IS NULL;
  `);
  // UNIQUE 인덱스를 타입 포함으로 교체 (즉시할인+다운로드 동시 등록 허용)
  try {
    await pool.query(`DROP INDEX IF EXISTS fixed_discounts_unique`);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS fixed_discounts_unique
        ON fixed_discounts(user_id, option_id, start_date, discount_type)
    `);
  } catch(e) { console.warn('[db] fixed_discounts_unique 재생성 스킵:', e.message); }

  // 성능 인덱스 추가 — 각 쿼리를 개별 실행 (pg는 멀티스테이트먼트를 신뢰할 수 없음)
  const perfIndexes = [
    'CREATE INDEX IF NOT EXISTS idx_orders_order_number ON orders(order_number)',
    'CREATE INDEX IF NOT EXISTS idx_orders_user_id      ON orders(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_orders_user_order   ON orders(user_id, order_number)',
    'CREATE INDEX IF NOT EXISTS idx_ad_reports_user_id  ON ad_reports(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_ad_reports_date     ON ad_reports(user_id, report_date)',
    'CREATE INDEX IF NOT EXISTS idx_returns_user_id     ON returns(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_returns_receipt     ON returns(user_id, receipt_number)',
    'CREATE INDEX IF NOT EXISTS idx_orders_user_platform_date ON orders(user_id, platform, order_date)',
    'CREATE INDEX IF NOT EXISTS idx_ad_reports_user_platform  ON ad_reports(user_id, platform, report_date)',
    'CREATE INDEX IF NOT EXISTS idx_returns_user_platform     ON returns(user_id, platform)',
    'CREATE INDEX IF NOT EXISTS idx_coupons_user_platform     ON coupons(user_id, platform)',
  ];
  for (const sql of perfIndexes) {
    try { await pool.query(sql); } catch(e) { console.warn('[db] 인덱스 생성 스킵:', e.message); }
  }

  // 쿠폰 unique index: 생성 전 중복 coupon_id 제거
  try {
    await pool.query(`
      DELETE FROM coupons c1
      USING coupons c2
      WHERE c1.id > c2.id
        AND c1.user_id  = c2.user_id
        AND c1.coupon_id = c2.coupon_id
        AND c1.coupon_id IS NOT NULL
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_coupons_coupon_id
        ON coupons(user_id, coupon_id)
        WHERE coupon_id IS NOT NULL
    `);
  } catch(e) { console.warn('[db] coupons unique index 스킵:', e.message); }

  // 팀 기능 — 계정 공유 테이블
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS account_shares (
        id             SERIAL PRIMARY KEY,
        owner_user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        member_email   TEXT NOT NULL,
        member_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status         TEXT NOT NULL DEFAULT 'active',
        created_at     TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(owner_user_id, member_email)
      );
      CREATE INDEX IF NOT EXISTS idx_shares_member ON account_shares(member_user_id);
      CREATE INDEX IF NOT EXISTS idx_shares_email  ON account_shares(LOWER(member_email));
    `);
  } catch(e) { console.warn('[db] account_shares 마이그레이션 스킵:', e.message); }

  // orders 우편번호 컬럼 (발주서용)
  try {
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS recipient_zipcode VARCHAR(20) DEFAULT NULL`);
  } catch(e) { console.warn('[db] orders recipient_zipcode 마이그레이션 스킵:', e.message); }

  // orders 발주 상태 컬럼
  try {
    await pool.query(`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS ordered_at           TIMESTAMPTZ DEFAULT NULL;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS ordered_supplier_id  INTEGER     DEFAULT NULL;
    `);
  } catch(e) { console.warn('[db] orders 발주 컬럼 마이그레이션 스킵:', e.message); }
  // orders 배송메시지
  try {
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_msg TEXT DEFAULT NULL`);
  } catch(e) { console.warn('[db] orders delivery_msg 컬럼 마이그레이션 스킵:', e.message); }

  // users 보내는사람 정보 컬럼
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS sender_name    TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS sender_phone   TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS sender_address TEXT;
    `);
  } catch(e) { console.warn('[db] users sender 컬럼 마이그레이션 스킵:', e.message); }

  console.log('[db] Tables ready');
}

module.exports = { pool, initDB };
