const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
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
    ALTER TABLE products     ADD COLUMN IF NOT EXISTS image_url   TEXT;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS supply_price INTEGER;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS sale_price   INTEGER;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS stock        INTEGER;
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS tax_type     VARCHAR(20);
    ALTER TABLE price_history ADD COLUMN IF NOT EXISTS shipping_fee INTEGER;
  `);

  console.log('[db] Tables ready');
}

module.exports = { pool, initDB };
