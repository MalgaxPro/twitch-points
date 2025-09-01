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
  const who = (req.cookies?.user_login_lc || req.cookies?.user_login || '').toLowerCase();
  if (who === 'malgax') return next();
  if (req.method === 'GET') return next();
  return res.status(403).json({ error: 'forbidden' });
});
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
  const loginShown = req.cookies?.user_login;
  const loginLc    = (req.cookies?.user_login_lc || req.cookies?.user_login || '').toLowerCase();
  if (!loginLc) return res.status(401).json({ error: 'unauthorized' });
  res.json({ login: loginShown || loginLc, login_lc: loginLc });
});
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

// ======== TWITCH OAUTH (login popup) ========
const TW_CID  = process.env.TWITCH_CLIENT_ID;
const TW_SEC  = process.env.TWITCH_CLIENT_SECRET;
const TW_RED  = process.env.TWITCH_REDIRECT_URI || 'https://api.malgax.com/auth/twitch/callback';
const APP_ORI = process.env.APP_ORIGIN || 'https://www.malgax.com';

// piccola utility per state anti-CSRF
function randState(){ return [...crypto.getRandomValues(new Uint8Array(24))].map(b=>b.toString(16).padStart(2,'0')).join(''); }

// per Node < 20:
const nodeMajor = parseInt(process.versions.node.split('.')[0],10);
const _fetch = (global.fetch && nodeMajor>=18) ? global.fetch : (...args)=>import('node-fetch').then(m=>m.default(...args));
const _crypto = (global.crypto && global.crypto.getRandomValues) ? global.crypto : require('crypto').webcrypto;

// GET /auth/twitch
app.get('/auth/twitch', async (req, res) => {
  try{
    const returnTo = req.query.return_to || req.get('referer') || (APP_ORI + '/');
    const stateObj = { s: [..._crypto.getRandomValues(new Uint8Array(12))].map(b=>b.toString(16).padStart(2,'0')).join(''), r: returnTo };
    const state = Buffer.from(JSON.stringify(stateObj)).toString('base64url');

    const params = new URLSearchParams({
      client_id: TW_CID,
      redirect_uri: TW_RED,
      response_type: 'code',
      scope: 'user:read:email', // opzionale, per prendere email; per il login base non è indispensabile
      state
    });
    return res.redirect('https://id.twitch.tv/oauth2/authorize?' + params.toString());
  }catch(e){
    console.error('auth/twitch err', e);
    res.status(500).send('Auth error');
  }
});

// GET /auth/twitch/callback
app.get('/auth/twitch/callback', async (req, res) => {
  // --- Added: store both display name and lowercase login in cookies ---
  const twitchUser = user?.data?.[0] || {};
  const login_lc = (twitchUser.login || '').toLowerCase();
  const display   = twitchUser.display_name || twitchUser.login;
  // cookie to show proper case on the site
  res.cookie('user_login', display, {
    httpOnly: false, sameSite: 'none', secure: true, path: '/', maxAge: 7*24*60*60*1000
  });
  // cookie for comparisons (always lowercase)
  res.cookie('user_login_lc', login_lc, {
    httpOnly: false, sameSite: 'none', secure: true, path: '/', maxAge: 7*24*60*60*1000
  });

  try{
    const { code, state } = req.query;
    if(!code || !state) return res.status(400).send('Missing code/state');

    let returnTo = APP_ORI + '/';
    try{
      const st = JSON.parse(Buffer.from(String(state), 'base64url').toString('utf8'));
      if (st?.r) returnTo = st.r;
    }catch{}

    // Scambio code → token
    const body = new URLSearchParams({
      client_id: TW_CID,
      client_secret: TW_SEC,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: TW_RED
    });

    const tok = await _fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type':'application/x-www-form-urlencoded' },
      body
    }).then(r=>r.json());

    if(!tok.access_token) {
      console.error('token error', tok);
      return res.redirect(returnTo);
    }

    // Prendo l'utente
    const user = await _fetch('https://api.twitch.tv/helix/users', {
      headers: {
        'Authorization': `Bearer ${tok.access_token}`,
        'Client-Id': TW_CID
      }
    }).then(r=>r.json());

    const login = (user?.data && user.data[0]?.login) || '';
    if(!login){
      console.error('no twitch login', user);
      return res.redirect(returnTo);
    }

    // Set cookie di sessione lato API (cross-site verso www)
    res.cookie('user_login', login.toLowerCase(), {
      httpOnly: false,         // il frontend non legge mai direttamente, ma teniamolo semplice
      sameSite: 'none',        // necessario per cookie cross-site
      secure: true,            // richiesto da SameSite=None
      path: '/',
      maxAge: 7*24*60*60*1000  // 7 giorni
    });

    // Torno alla pagina che aveva aperto il popup
    return res.redirect(returnTo);
  }catch(e){
    console.error('auth/callback err', e);
    res.status(500).send('Auth error');
  }
});

// GET /logout
app.get('/logout', (req, res) => {
  const returnTo = req.query.return_to || APP_ORI + '/';
  res.clearCookie('user_login', { path:'/', sameSite:'none', secure:true });
  res.redirect(returnTo);
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
