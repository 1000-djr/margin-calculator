const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS b2b_sites (
      id        SERIAL PRIMARY KEY,
      name      VARCHAR(100) NOT NULL,
      url       VARCHAR(500) NOT NULL,
      login_url VARCHAR(500),
      username_env VARCHAR(100),
      password_env VARCHAR(100),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS products (
      id          SERIAL PRIMARY KEY,
      site_id     INTEGER REFERENCES b2b_sites(id) ON DELETE CASCADE,
      name        VARCHAR(200) NOT NULL,
      unit        VARCHAR(50),
      external_id VARCHAR(200),
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (site_id, external_id)
    );

    CREATE TABLE IF NOT EXISTS price_history (
      id         SERIAL PRIMARY KEY,
      product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
      price      INTEGER NOT NULL,
      crawled_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('[db] Tables ready');
}

module.exports = { pool, initDB };
