const express    = require('express');
const path       = require('path');
const session    = require('express-session');
const connectPg  = require('connect-pg-simple');
const { initDB, pool } = require('./db');
const { router: authRouter, passport } = require('./auth');
const apiRouter  = require('./api');
const scheduler  = require('./scheduler');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ─── 세션 ────────────────────────────────────────────────────────────────────
const sessionConfig = {
  secret:            process.env.SESSION_SECRET || 'margin-calc-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  cookie:            { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true },
};
if (process.env.DATABASE_URL) {
  const PgStore = connectPg(session);
  sessionConfig.store = new PgStore({ pool, createTableIfMissing: true });
}
app.use(session(sessionConfig));

// ─── Passport ────────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ─── 라우터 ──────────────────────────────────────────────────────────────────
app.use('/', authRouter);
app.use('/api', apiRouter);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── 서버 시작 ───────────────────────────────────────────────────────────────
(async () => {
  if (process.env.DATABASE_URL) {
    await initDB();
    scheduler.start();
  } else {
    console.warn('[server] DATABASE_URL 없음 — DB 기능 비활성화');
  }
  app.listen(PORT, () => console.log(`[server] http://localhost:${PORT}`));
})();
