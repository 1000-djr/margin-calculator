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
        const { rows } = await pool.query(
          `INSERT INTO users (google_id, email, name, picture)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (google_id) DO UPDATE
             SET email = EXCLUDED.email,
                 name  = EXCLUDED.name,
                 picture = EXCLUDED.picture
           RETURNING *`,
          [profile.id, email, profile.displayName, picture]
        );
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

// Google 콜백
router.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/?auth=failed' }),
  (req, res) => res.redirect('/')
);

// 로그아웃
router.post('/auth/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

module.exports = { router, passport };
