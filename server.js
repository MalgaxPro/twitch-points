// server.js — backend minimo per malgax: login dev + carte + classifiche + admin

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const APP_ORIGIN = process.env.APP_ORIGIN || 'https://www.malgax.com';
const PORT = process.env.PORT || 3000;

const app = express();
app.set('trust proxy', 1);

app.use(cors({
  origin: [APP_ORIGIN],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// ---------- Postgres ----------
if (!process.env.DATABASE_URL) {
  console.error('❌ Missing env DATABASE_URL');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- Utils ----------
function getUserLogin(req) {
  // 1) cookie da /auth/dev-login
  const c = req.cookies?.user_login;
  if (c) return String(c).toLowerCase();
  // 2) header manuale per test
  const h = req.get('x-user-login');
  return String(h || '').toLowerCase();
}
function ensureIsAdmin(req, res, next) {
  const who = getUserLogin(req);
  if (who === 'malgax') return next();
  // lascio aperti i GET per leggere; togli questa riga se vuoi chiuderli
  if (req.method === 'GET') return next();
  return res.status(403).json({ error: 'forbidden' });
}

// ---------- Init: VIEW per admin ----------
async function ensureView() {
  const createView = `
    CREATE OR REPLACE VIEW admin_used_cards AS
    SELECT
      pt.id,                          -- Event ID
      pt.created_at,                  -- Quando
      u.username AS user_login,       -- Utente (da users)
      pt.item_id,
      COALESCE(pt.done, false) AS done,
      i.name AS item_name,            -- Carta
      i.kind AS kind                  -- Tipo
    FROM point_transactions pt
    LEFT JOIN users u ON u.id = pt.user_id
    JOIN items i ON i.id = pt.item_id
    WHERE pt.type = 'use';
  `;
  await pool.query(createView).catch(()=>{});
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_created_at ON point_transactions (created_at DESC);`).catch(()=>{});
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_done ON point_transactions (done);`).catch(()=>{});
}

// ---------- Rotte base ----------
app.get('/', (req, res) => res.json({ ok: true, service: 'malgax-api', ts: new Date().toISOString() }));
app.get('/healthz', (req, res) => res.status(200).send('ok'));

// Piccolo /me basato sul cookie
app.get('/me', (req, res) => {
  const login = getUserLogin(req);
  if (!login) return res.status(401).json({ error: 'unauthorized' });
  res.json({ login });
});

// ---------- DEV LOGIN (sostituisce momentaneamente /auth/twitch) ----------
app.post('/auth/dev-login', (req, res) => {
  const login = String(req.body?.login || '').toLowerCase().trim();
  if (!login) return res.status(400).json({ error: 'missing_login' });
  res.cookie('user_login', login, {
    httpOnly: false,
    sameSite: 'none',
    secure: true,
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  res.json({ ok: true, login });
});

app.post('/auth/dev-logout', (req, res) => {
  res.clearCookie('user_login', { path: '/', sameSite: 'none', secure: true });
  res.json({ ok: true });
});

// ---------- INVENTORY (carte) ----------
app.get('/inventory', async (req, res) => {
  try {
    const q = `
      SELECT id, slug, name, kind, cost_points, image_url, description
      FROM items
      ORDER BY name ASC;
    `;
    const { rows } = await pool.query(q);
    res.json({ items: rows });
  } catch (e) {
    console.error('ERR /inventory', e);
    // non mando 500: restituisco array vuoto così il frontend non esplode
    res.json({ items: [] });
  }
});

// ---------- LEADERBOARD ----------
app.get('/api/leaderboard/top', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const q = `
      SELECT id, username, total_points
      FROM users
      WHERE total_points IS NOT NULL
      ORDER BY total_points DESC, username ASC
      LIMIT $1;
    `;
    const { rows } = await pool.query(q, [limit]);
    res.json({ items: rows });
  } catch (e) {
    console.error('ERR /api/leaderboard/top', e);
    res.json({ items: [] });
  }
});

app.get('/api/leaderboard/unspent', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
    const q = `
      SELECT id, username, unspent_points
      FROM users
      WHERE unspent_points IS NOT NULL
      ORDER BY unspent_points DESC, username ASC
      LIMIT $1;
    `;
    const { rows } = await pool.query(q, [limit]);
    res.json({ items: rows });
  } catch (e) {
    console.error('ERR /api/leaderboard/unspent', e);
    res.json({ items: [] });
  }
});

// ---------- ADMIN: lista usi carte ----------
app.get('/admin/used-cards', ensureIsAdmin, async (req, res) => {
  try {
    const { kind, status = 'all', user, item, from, to, limit = 100 } = req.query;
    const where = ['1=1'];
    const params = [];

    if (kind) { params.push(kind); where.push(`kind = $${params.length}`); }
    if (user) { params.push(user); where.push(`LOWER(user_login) = LOWER($${params.length})`); }
    if (item) { params.push(`%${item}%`); where.push(`LOWER(item_name) LIKE LOWER($${params.length})`); }
    if (from) { params.push(new Date(from)); where.push(`created_at >= $${params.length}`); }
    if (to)   { params.push(new Date(to));   where.push(`created_at <= $${params.length}`); }
    if (status === 'pending') where.push(`done = false`);
    if (status === 'done')    where.push(`done = true`);

    params.push(Number(limit)); const limIdx = params.length;

    const sql = `
      SELECT id, created_at, user_login, item_id, done, item_name, kind
      FROM admin_used_cards
      WHERE ${where.join(' AND ')}
      ORDER BY created_at DESC
      LIMIT $${limIdx};
    `;
    const { rows } = await pool.query(sql, params);
    res.json({ items: rows });
  } catch (err) {
    console.error('ERR /admin/used-cards', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// ---------- ADMIN: segna fatto ----------
app.post('/admin/used-cards/complete', ensureIsAdmin, async (req, res) => {
  try {
    const { id, done = true } = req.body || {};
    if (!id) return res.status(400).json({ error: 'missing_id' });
    await pool.query(`UPDATE point_transactions SET done = $1 WHERE id = $2`, [!!done, id]);
    res.json({ ok: true, id, done: !!done });
  } catch (err) {
    console.error('ERR /admin/used-cards/complete', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// ---------- Avvio ----------
(async () => {
  try {
    await pool.connect();
    await ensureView(); // non fallire il deploy se la view non si crea
    app.listen(PORT, () => console.log(`✅ API up on :${PORT} (origin ${APP_ORIGIN})`));
  } catch (e) {
    console.error('❌ Startup error:', e);
    process.exit(1);
  }
})();
