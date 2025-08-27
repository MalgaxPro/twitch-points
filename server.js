// server.js — Express + Twitch OAuth + EventSub + Postgres (Neon)
require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const TwitchStrategy = require('passport-twitch-new').Strategy;
const crypto = require('crypto');
const { Pool } = require('pg');

// ---------- DB (Postgres/Neon) ----------
const connectionString =
  process.env.DATABASE_URL ||
  'postgresql://neondb_owner:npg_TRLm7Wk6thJU@ep-frosty-brook-a2lqxhp8-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false }, // richiesto da Neon
});

// Migrazione iniziale
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      twitch_id TEXT UNIQUE NOT NULL,
      username TEXT,
      total_points INTEGER NOT NULL DEFAULT 0,
      unspent_points INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tid ON users(twitch_id);
  `);
}
initDb().catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});

// ---------- APP ----------
const app = express();
app.set('trust proxy', 1);

// Parsers (raw SOLO per /eventsub)
app.use('/eventsub', express.raw({ type: '*/*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Static
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// Session
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax', secure: 'auto' },
}));

// ---------- Passport Twitch ----------
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'https://www.malgax.com';

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, rows[0] || null);
  } catch (e) { done(e); }
});

passport.use(new TwitchStrategy({
  clientID: process.env.TWITCH_CLIENT_ID,
  clientSecret: process.env.TWITCH_CLIENT_SECRET,
  callbackURL: process.env.TWITCH_CALLBACK_URL, // es: https://api.malgax.com/auth/twitch/callback
  scope: ['user:read:email', 'channel:read:subscriptions']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const twitch_id = String(profile.id);
    const username = profile.display_name || profile.username || profile.login || ('user_' + twitch_id);

    // upsert user (solo username)
    const { rows } = await pool.query(
      `INSERT INTO users (twitch_id, username)
       VALUES ($1, $2)
       ON CONFLICT (twitch_id) DO UPDATE
         SET username = EXCLUDED.username,
             updated_at = NOW()
       RETURNING *`,
      [twitch_id, username]
    );
    return done(null, rows[0]);
  } catch (e) {
    return done(e);
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ---------- Auth routes ----------
app.get('/auth/twitch', passport.authenticate('twitch'));
app.get('/auth/twitch/callback',
  passport.authenticate('twitch', { failureRedirect: '/auth-failed.html' }),
  (req, res) => {
    if (req.query.popup === '1') {
      return res.type('html').send(
        `<script>window.opener && window.opener.postMessage({type:'login'}, '${FRONTEND_ORIGIN}'); window.close();</script>`
      );
    }
    res.redirect('/profile.html');
  }
);

app.get('/logout', (req, res) => {
  req.logout?.(() => {});
  req.session?.destroy?.(() => {});
  const popup = req.query.popup === '1';
  if (popup) {
    return res.type('html').send(
      `<script>window.opener && window.opener.postMessage({type:'logout'}, '${FRONTEND_ORIGIN}'); window.close();</script>`
    );
  }
  res.redirect('/');
});

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

async function addPoints(twitch_id, username, amount) {
  // crea/aggiorna e somma i punti in un colpo solo
  await pool.query(
    `INSERT INTO users (twitch_id, username, total_points, unspent_points)
     VALUES ($1, $2, $3, $3)
     ON CONFLICT (twitch_id) DO UPDATE
       SET username = EXCLUDED.username,
           total_points   = users.total_points   + EXCLUDED.total_points,
           unspent_points = users.unspent_points + EXCLUDED.unspent_points,
           updated_at = NOW()`,
    [twitch_id, username || ('user_' + twitch_id), amount]
  );
}

// ---------- API ----------
app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/me', async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const { rows } = await pool.query(
    'SELECT username, total_points, unspent_points FROM users WHERE id=$1',
    [req.user.id]
  );
  res.json(rows[0] || {});
});

app.get('/leaderboard', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT username, total_points AS points
     FROM users
     ORDER BY total_points DESC, username ASC
     LIMIT 200`
  );
  res.json(rows);
});

app.get('/unspent', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT username, unspent_points AS points
     FROM users
     ORDER BY unspent_points DESC, username ASC
     LIMIT 200`
  );
  res.json(rows);
});

// spend (per futuro shop)
app.post('/spend', requireAuth, async (req, res) => {
  const amount = parseInt(req.body.amount, 10);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: 'amount must be a positive integer' });
  }
  const { rows } = await pool.query(
    `UPDATE users
     SET unspent_points = unspent_points - $1,
         updated_at = NOW()
     WHERE id = $2 AND unspent_points >= $1
     RETURNING total_points, unspent_points`,
    [amount, req.user.id]
  );
  if (!rows[0]) return res.status(400).json({ error: 'not enough unspent points' });
  res.json(rows[0]);
});

// ---------- EventSub ----------
const EVENTSUB_SECRET = process.env.TWITCH_EVENTSUB_SECRET || 'dev-secret';

function verifyTwitchSignature(req) {
  const msgId = req.header('Twitch-Eventsub-Message-Id') || '';
  const ts = req.header('Twitch-Eventsub-Message-Timestamp') || '';
  const sig = req.header('Twitch-Eventsub-Message-Signature') || '';
  const body = req.body instanceof Buffer ? req.body : Buffer.from(req.body || '');

  const hmacMessage = msgId + ts + body.toString('utf8');
  const expected = 'sha256=' + crypto.createHmac('sha256', EVENTSUB_SECRET).update(hmacMessage).digest('hex');

  const a = Buffer.from(expected);
  const b = Buffer.from(sig);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

app.post('/eventsub', async (req, res) => {
  let payload = {};
  try { payload = JSON.parse(req.body.toString('utf8') || '{}'); }
  catch { return res.status(400).send('bad json'); }

  const msgType = req.header('Twitch-Eventsub-Message-Type');

  if (msgType !== 'webhook_callback_verification') {
    if (!verifyTwitchSignature(req)) return res.status(403).send('Invalid signature');
  }

  if (msgType === 'webhook_callback_verification') {
    return res.type('text/plain').send(payload.challenge);
  }

  if (msgType === 'notification') {
    const subType = payload.subscription?.type;
    const ev = payload.event || {};
    const amount = 1; // 1 punto per sub/gift

    if (subType === 'channel.subscribe') {
      const twitch_id = String(ev.user_id || '');
      const username = ev.user_name || ev.user_login || '';
      if (twitch_id) await addPoints(twitch_id, username, amount);
    }
    if (subType === 'channel.subscription.gift') {
      const twitch_id = String(ev.user_id || '');
      const username = ev.user_name || ev.user_login || '';
      if (twitch_id) await addPoints(twitch_id, username, amount);
    }
    return res.status(204).end();
  }

  if (msgType === 'revocation') {
    return res.status(204).end();
  }

  res.status(204).end();
});

// ---------- Avvio ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server avviato su http://localhost:${PORT}`);
});
