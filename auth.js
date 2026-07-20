/**
 * auth.js
 * Passport Google OAuth 2.0 설정 및 인증 라우터
 */

const express  = require('express');
const passport = require('passport');
const router   = express.Router();
const { pool } = require('./db');

// Google 전략 — 환경변수가 있을 때만 등록
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  const { Strategy: GoogleStrategy } = require('passport-google-oauth20');

  passport.use(new GoogleStrategy(
    {
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email   = profile.emails?.[0]?.value  || '';
        const picture = profile.photos?.[0]?.value  || '';
        const isAdmin = email === (process.env.ADMIN_EMAIL || '');
        const { rows } = await pool.query(
          `INSERT INTO users (google_id, email, name, picture, status, is_admin)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (google_id) DO UPDATE
             SET email   = EXCLUDED.email,
                 name    = EXCLUDED.name,
                 picture = EXCLUDED.picture,
                 is_admin = CASE WHEN EXCLUDED.is_admin THEN TRUE ELSE users.is_admin END
           RETURNING *`,
          [profile.id, email, profile.displayName, picture,
           isAdmin ? 'active' : 'pending',
           isAdmin]
        );
        // 로그인 성공 후: 이 이메일로 초대된 account_shares 행에 member_user_id 연결
        try {
          await pool.query(
            `UPDATE account_shares
                SET member_user_id = $1
              WHERE LOWER(member_email) = LOWER($2)
                AND member_user_id IS NULL`,
            [rows[0].id, email]
          );
        } catch (shareErr) {
          console.warn('[auth] account_shares 자동 연결 실패:', shareErr.message);
        }

        return done(null, rows[0]);
      } catch (err) {
        return done(err);
      }
    }
  ));
}

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, rows[0] || null);
  } catch (err) {
    done(err);
  }
});

// ─── 라우터 ──────────────────────────────────────────────────────────────────

// Google 로그인 시작
router.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.redirect('/?error=google_not_configured');
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// ── 접근 제한 판정 유틸 ──────────────────────────────────────────────────────
function getAccessDeniedReason(user) {
  if (!user) return null;
  if (user.status === 'pending')  return 'pending';
  if (user.status === 'blocked')  return 'blocked';
  if (user.status === 'active' && user.expires_at && new Date(user.expires_at) < new Date()) {
    return 'expired';
  }
  return null; // 정상 접근
}

// Google 콜백
router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?auth=failed' }),
  (req, res) => {
    const reason = getAccessDeniedReason(req.user);
    if (reason) return res.redirect('/pending?reason=' + reason);
    res.redirect('/');
  }
);

// 승인 대기 / 차단 / 만료 페이지
router.get('/pending', (req, res) => {
  const reason = req.query.reason || getAccessDeniedReason(req.user) || 'pending';
  const name   = req.user?.name || '';

  const configs = {
    pending: { icon: '⏳', title: '관리자 승인 대기 중입니다.', msg:  '서비스 이용 신청이 접수되었습니다.<br>관리자 승인 후 이용하실 수 있습니다.' },
    blocked: { icon: '🚫', title: '접근이 차단되었습니다.',      msg:  '이 계정은 사용이 차단되었습니다.<br>문의가 필요하시면 관리자에게 연락해 주세요.' },
    expired: { icon: '📅', title: '사용 기간이 만료되었습니다.', msg:  '이용 기간이 종료되었습니다.<br>연장이 필요하시면 관리자에게 연락해 주세요.' },
  };
  const { icon, title, msg } = configs[reason] || configs.pending;

  res.send(`<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>접근 제한</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:#f5f5f7;display:flex;align-items:center;justify-content:center;
       min-height:100vh;color:#1d1d1f}
  .card{background:#fff;border-radius:18px;padding:48px 40px;text-align:center;
        max-width:400px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,.08)}
  .icon{font-size:48px;margin-bottom:20px}
  h1{font-size:20px;font-weight:600;margin-bottom:12px}
  p{font-size:15px;color:#6e6e73;line-height:1.6;margin-bottom:24px}
  a{display:inline-block;padding:12px 28px;background:#1d1d1f;color:#fff;
    border-radius:980px;text-decoration:none;font-size:14px;font-weight:500}
  a:hover{background:#3a3a3c}
</style>
</head>
<body>
<div class="card">
  <div class="icon">${icon}</div>
  <h1>${title}</h1>
  <p>${name ? name + '님, ' : ''}${msg}</p>
  <a href="/auth/logout-get">로그아웃</a>
</div>
</body>
</html>`);
});

// GET 로그아웃 (pending 페이지에서 사용)
router.get('/auth/logout-get', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// 로그아웃
router.post('/auth/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

module.exports = { router, passport };
