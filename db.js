const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
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

  // ad_reports 마이그레이션: 원본 전체 데이터 저장 컬럼 추가
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
      UNIQUE (user_id, report_date, option_id, keyword)
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

  // coupons 테이블 마이그레이션 (기존 테이블에 신규 컬럼 추가)
  await pool.query(`
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS coupon_id       BIGINT;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS discount_amount NUMERIC(12,2) DEFAULT 0;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS start_at        TIMESTAMPTZ;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS end_at          TIMESTAMPTZ;
    ALTER TABLE coupons ADD COLUMN IF NOT EXISTS option_ids      JSONB DEFAULT '[]';
  `);

  await pool.query(`
    ALTER TABLE b2b_prices ADD COLUMN IF NOT EXISTS start_date  DATE;
    ALTER TABLE b2b_prices ADD COLUMN IF NOT EXISTS end_date    DATE;
    ALTER TABLE orders     ADD COLUMN IF NOT EXISTS is_excluded BOOLEAN DEFAULT FALSE;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_name_mapping (
      id                SERIAL PRIMARY KEY,
      user_id           INTEGER REFERENCES users(id) ON DELETE CASCADE,
      registered_name   TEXT NOT NULL,
      b2b_name          TEXT NOT NULL,
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, registered_name)
    );
  `);

  console.log('[db] Tables ready');
}

module.exports = { pool, initDB };
