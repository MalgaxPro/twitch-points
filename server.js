// server.js — API minimale per carte usate (Render + Neon)

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const APP_ORIGIN = process.env.APP_ORIGIN || 'https://www.malgax.com';
const PORT = process.env.PORT || 3000;

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: [APP_ORIGIN], credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ------------ Postgres (Neon) ------------
if (!process.env.DATABASE_URL) {
  console.error('❌ Missing env DATABASE_URL');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ------------ Util ------------
function getUserLogin(req) {
  // 1) se hai un middleware auth che mette req.user:
  const u =
    (req.user && (req.user.login || req.user.username)) ||
    // 2) header manuale per test (es. con Postman):  X-User-Login: malgax
    req.get('x-user-login') ||
    // 3) cookie per test (vedi /auth/dev-login): user_login=malgax
    req.cookies.user_login ||
    '';
  return String(u || '').toLowerCase();
}

function ensureIsAdmin(req, res, next) {
  const who = getUserLogin(req);
  if (who === 'malgax') return next();
  // Consenti lettura a tutti per comodità (toglimi se vuoi chiudere):
  if (req.method === 'GET') return next();
  return res.status(403).json({ error: 'forbidden' });
}

// ------------ Init: crea/aggiorna VIEW standard ------------
async function ensureView() {
  const sql = `
    CREATE OR REPLACE VIEW admin_used_cards AS
    SELECT
      pt.id,                                   -- Event ID
      pt.created_at,                           -- Quando
      COALESCE(pt.user_login, u.username) AS user_login,  -- Utente
      pt.item_id,
      COALESCE(pt.done, false) AS done,
      i.name AS item_name,                     -- Carta
      i.kind AS kind                           -- Tipo (creature/incantesimo/istantanea)
    FROM point_transactions pt
    LEFT JOIN users u ON u.id = pt.user_id
    JOIN items i ON i.id = pt.item_id
    WHERE pt.event_type = 'use';
  `;
  await pool.query(sql);
  // indici consigliati (idempotenti)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_created_at ON point_transactions (created_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pt_done ON point_transactions (done);`);
}

// ------------ Rotte base ------------
app.get('/', (req, res) => res.json({ ok: true, service: 'malgax-api', ts: new Date().toISOString() }));
app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.get('/me', (req, res) => {
  const login = getUserLogin(req);
  if (!login) return res.status(401).json({ error: 'unauthorized' });
  res.json({ login }); // forma minima usata dal frontend
});

// (Facoltativo) dev login via cookie per test su Render senza SSO.
// Abilitalo aggiungendo DEV_AUTH=true nelle env se vuoi usarlo.
if (process.env.DEV_AUTH === 'true') {
  app.post('/auth/dev-login', (req, res) => {
    const login = String(req.body?.login || '').toLowerCase();
    if (!login) return res.status(400).json({ error: 'missing login' });
    res.cookie('user_login', login, {
      httpOnly: false,
      sameSite: 'lax',
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      domain: undefined, // lasciare undefined su Render
      path: '/',
    });
    res.json({ ok: true, login });
  });
  app.post('/auth/dev-logout', (_, res) => {
    res.clearCookie('user_login', { path: '/' });
    res.json({ ok: true });
  });
}

// ------------ Rotte ADMIN --------------

// GET /admin/used-cards
// Filtri: kind=creature|incantesimo|istantanea, status=all|pending|done,
//         user, item, from, to, limit
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

// POST /admin/used-cards/complete  body: { id, done:true|false }
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

// ------------ Avvio ------------
(async () => {
  try {
    await pool.connect(); // apre una connessione per validare l'URL
    await ensureView();
    app.listen(PORT, () => {
      console.log(`✅ API up on :${PORT} (origin ${APP_ORIGIN})`);
    });
  } catch (e) {
    console.error('❌ Startup error:', e);
    process.exit(1);
  }
})();
