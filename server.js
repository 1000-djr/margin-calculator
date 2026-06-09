const express    = require('express');
const path       = require('path');
const session    = require('express-session');
const connectPg  = require('connect-pg-simple');
const { initDB, pool } = require('./db');
const { router: authRouter, passport } = require('./auth');
const apiRouter   = require('./api');
const adminRouter = require('./admin');
const scheduler   = require('./scheduler');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.get('/favicon.svg', (req, res) => res.sendFile(path.join(__dirname, 'public', 'favicon.svg')));
app.use(express.static(path.join(__dirname)));
app.use('/public', express.static(path.join(__dirname, 'public')));

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

// ─── 대리접속 미들웨어 ───────────────────────────────────────────────────────
// passport 세션 복원 후, impersonating_user_id가 있으면 req.user를 교체
app.use(async (req, res, next) => {
  if (req.session?.impersonating_user_id && req.user?.is_admin) {
    try {
      const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.impersonating_user_id]);
      if (rows.length) {
        req.originalAdmin = req.user;   // 원래 어드민 보관
        req.user = rows[0];             // 대리접속 유저로 교체
      }
    } catch (e) {
      console.error('[impersonate] 유저 조회 실패', e);
    }
  }
  next();
});

// ─── 라우터 ──────────────────────────────────────────────────────────────────
app.use('/', authRouter);
app.use('/api', apiRouter);
app.use('/', adminRouter);

app.get('/', (req, res) => {
  // 어드민 대리접속 중이면 status 체크 건너뜀 (impersonated user의 status로 어드민이 차단되는 버그 방지)
  if (req.user && !req.originalAdmin) {
    const { status, expires_at } = req.user;
    if (status === 'pending') return res.redirect('/pending?reason=pending');
    if (status === 'blocked') return res.redirect('/pending?reason=blocked');
    if (status === 'active' && expires_at && new Date(expires_at) < new Date()) {
      return res.redirect('/pending?reason=expired');
    }
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── 서버 시작 ───────────────────────────────────────────────────────────────
(async () => {
  if (process.env.DATABASE_URL) {
    try {
      await initDB();
      scheduler.start();
    } catch (e) {
      console.error('[server] initDB 실패 — 서버는 계속 실행됩니다:', e.message);
    }
  } else {
    console.warn('[server] DATABASE_URL 없음 — DB 기능 비활성화');
  }
  app.listen(PORT, () => console.log(`[server] http://localhost:${PORT}`));
})();
