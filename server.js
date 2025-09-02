
require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const cors = require('cors');
const passport = require('passport');
const TwitchStrategy = require('passport-twitch-new').Strategy;
const { Pool } = require('pg');

const {
  PORT = 3000,
  SESSION_SECRET = 'dev_secret_change_me',
  TWITCH_CLIENT_ID,
  TWITCH_CLIENT_SECRET,
  TWITCH_CALLBACK_URL, // es: https://api.malgax.com/auth/twitch/callback
  TWITCH_EVENTSUB_SECRET, // segreto per validare EventSub
  DATABASE_URL // stringa Neon
} = process.env;

if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET || !TWITCH_CALLBACK_URL) {
  console.warn('[WARN] Twitch OAuth env non completi. Verifica .env su Render.');
}
if (!DATABASE_URL) {
  console.warn('[WARN] DATABASE_URL mancante (Neon).');
}
if (!TWITCH_EVENTSUB_SECRET) {
  console.warn('[WARN] TWITCH_EVENTSUB_SECRET mancante (EventSub).');
}

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: ['https://www.malgax.com', 'https://malgax.com'], credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    maxAge: 1000*60*60*24*30
  }
}));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

passport.serializeUser((user, done) => done(null, { id: user.id, twitch_id: user.twitch_id, username: user.username }));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new TwitchStrategy({
  clientID: TWITCH_CLIENT_ID,
  clientSecret: TWITCH_CLIENT_SECRET,
  callbackURL: TWITCH_CALLBACK_URL,
  scope: ['user:read:email', 'channel:read:subscriptions']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const tid = String(profile.id);
    const uname = profile.display_name || profile.username || profile.login || 'Utente';
    const upsert = await pool.query(`
      INSERT INTO users (twitch_id, username)
      VALUES ($1, $2)
      ON CONFLICT (twitch_id) DO UPDATE
        SET username = EXCLUDED.username, updated_at = NOW()
      RETURNING id, twitch_id, username, total_points, unspent_points
    `, [tid, uname]);
    done(null, upsert.rows[0]);
  } catch (e) {
    done(e);
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ---------- DB INIT ----------
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

    CREATE TABLE IF NOT EXISTS items (
      id SERIAL PRIMARY KEY,
      slug TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('creature','spell','instant')),
      cost_points INTEGER NOT NULL CHECK (cost_points > 0),
      image_url TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_items (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      quantity INTEGER NOT NULL CHECK (quantity >= 0),
      UNIQUE(user_id, item_id)
    );

    CREATE TABLE IF NOT EXISTS point_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK (type IN ('purchase','spend','grant','refund')),
      delta_points INTEGER NOT NULL,
      item_id INTEGER REFERENCES items(id),
      quantity INTEGER,
      client_token TEXT,
      points_before INTEGER NOT NULL,
      points_after INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_user_items_user ON user_items(user_id);
    CREATE INDEX IF NOT EXISTS idx_tx_user_created ON point_transactions(user_id, created_at DESC);
  `);
}
initDb().catch(err => {
  console.error('DB init error:', err);
  process.exit(1);
});

// ---------- Utils ----------
function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

async function grantPointsByTwitchId(client, twitch_id, username, delta) {
  const uRes = await client.query(`
    INSERT INTO users (twitch_id, username)
    VALUES ($1, $2)
    ON CONFLICT (twitch_id) DO UPDATE
      SET username = COALESCE(EXCLUDED.username, users.username),
          updated_at = NOW()
    RETURNING id, total_points, unspent_points
  `, [twitch_id, username || null]);
  const u = uRes.rows[0];
  const before = u.unspent_points;
  const after  = u.unspent_points + delta;
  await client.query(
    'UPDATE users SET total_points = total_points + $1, unspent_points = unspent_points + $1, updated_at=NOW() WHERE id=$2',
    [delta, u.id]
  );
  await client.query(`
    INSERT INTO point_transactions (user_id, type, delta_points, points_before, points_after)
    VALUES ($1, 'grant', $2, $3, $4)
  `, [u.id, delta, before, after]);
}

// ---------- OAuth ----------
app.get('/auth/twitch', (req, res, next) => {
  const isPopup = req.query.popup === '1';
  req.session.isPopup = isPopup;
  const state = isPopup ? 'popup' : 'redir';
  passport.authenticate('twitch', { state })(req, res, next);
});

// Dopo il login: mostra messaggio “login effettuato”, invia postMessage e tenta la chiusura.
app.get('/auth/twitch/callback', passport.authenticate('twitch', { failureRedirect: '/auth-failed.html' }), async (req, res) => {
  req.session.isPopup = undefined;
  res.type('html').send(`
✅ Login effettuato con successo

Puoi chiudere questa finestra e tornare al sito.
`);
});

app.get('/logout', (req, res, next) => {
  const isPopup = req.query.popup === '1' || req.session.isPopup === true;
  req.session.isPopup = undefined;
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => {
      if (isPopup) {
        res.type('html').send(`
👋 Logout eseguito

Puoi chiudere questa finestra.
`);
      } else {
        res.type('text').send('Logout eseguito. Puoi chiudere questa pagina.');
      }
    });
  });
});

// ---------- API ----------
app.get('/me', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  try {
    const { rows } = await pool.query(
      'SELECT id, twitch_id, username, total_points, unspent_points FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'not_found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/health', (req, res) => res.type('text').send('ok'));

app.get('/api/leaderboard', async (req, res) => {
  const by = (req.query.by === 'unspent') ? 'unspent_points' : 'total_points';
  try {
    const { rows } = await pool.query(
      `SELECT username, ${by} AS points FROM users ORDER BY ${by} DESC, username ASC LIMIT 100`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});
app.get('/api/leaderboard/top', (req, res) =>
  pool.query(`SELECT username, total_points AS points FROM users ORDER BY total_points DESC, username ASC LIMIT 100`)
    .then(r => res.json(r.rows)).catch(_ => res.status(500).json({ error: 'server_error' }))
);
app.get('/api/leaderboard/unspent', (req, res) =>
  pool.query(`SELECT username, unspent_points AS points FROM users ORDER BY unspent_points DESC, username ASC LIMIT 100`)
    .then(r => res.json(r.rows)).catch(_ => res.status(500).json({ error: 'server_error' }))
);

// ---------- SHOP & INVENTARIO ----------
app.get('/shop/items', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, slug, name, kind, cost_points, image_url, description FROM items ORDER BY cost_points ASC, name ASC`
  );
  res.json(rows);
});
app.post('/shop/purchase', requireAuth, async (req, res) => {
  const itemId = parseInt(req.body.item_id, 10);
  const qty = Math.max(1, parseInt(req.body.quantity || '1', 10));
  const idem = (req.headers['idempotency-key'] || '').toString().slice(0,128);
  if (!Number.isFinite(itemId) || itemId <= 0) {
    return res.status(400).json({ error: 'item_id non valido' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const uRes = await client.query('SELECT id, unspent_points FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
    if (!uRes.rows[0]) throw new Error('utente non trovato');
    const user = uRes.rows[0];
    const iRes = await client.query('SELECT id, name, cost_points FROM items WHERE id=$1', [itemId]);
    if (!iRes.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'item non trovato' });
    }
    const item = iRes.rows[0];
    const totalCost = item.cost_points * qty;
    if (user.unspent_points < totalCost) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'punti insufficienti' });
    }
    await client.query(`
      INSERT INTO user_items (user_id, item_id, quantity)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, item_id) DO UPDATE
        SET quantity = user_items.quantity + EXCLUDED.quantity
    `, [req.user.id, item.id, qty]);
    const after = user.unspent_points - totalCost;
    await client.query('UPDATE users SET unspent_points=$1, updated_at=NOW() WHERE id=$2', [after, req.user.id]);
    await client.query(`
      INSERT INTO point_transactions (user_id, type, delta_points, item_id, quantity, client_token, points_before, points_after)
      VALUES ($1, 'purchase', $2, $3, $4, NULLIF($5,''), $6, $7)
    `, [req.user.id, -totalCost, item.id, qty, idem, user.unspent_points, after]);
    await client.query('COMMIT');
    res.json({ ok: true, item: { id: item.id, name: item.name, cost_points: item.cost_points }, quantity: qty, cost: totalCost, unspent_after: after });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'purchase_failed', detail: e.message });
  } finally {
    client.release();
  }
});

app.get('/inventory', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT i.id AS item_id, i.slug, i.name, i.kind, i.image_url, i.description, ui.quantity
    FROM user_items ui
    JOIN items i ON i.id = ui.item_id
    WHERE ui.user_id = $1
    ORDER BY i.kind, i.name
  `, [req.user.id]);
  res.json(rows);
});

app.post('/inventory/use', requireAuth, async (req, res) => {
  const itemId = parseInt(req.body.item_id, 10);
  const qty = Math.max(1, parseInt(req.body.quantity || '1', 10));
  if (!Number.isFinite(itemId) || itemId <= 0) return res.status(400).json({ error: 'item_id non valido' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const qRes = await client.query('SELECT quantity FROM user_items WHERE user_id=$1 AND item_id=$2 FOR UPDATE', [req.user.id, itemId]);
    const have = qRes.rows[0]?.quantity || 0;
    if (have < qty) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'quantità insufficiente' });
    }
    await client.query('UPDATE user_items SET quantity = quantity - $1 WHERE user_id=$2 AND item_id=$3', [qty, req.user.id, itemId]);
    await client.query(`
      INSERT INTO point_transactions (user_id, type, delta_points, item_id, quantity, points_before, points_after)
      VALUES ($1, 'spend', 0, $2, $3,
        (SELECT unspent_points FROM users WHERE id=$1),
        (SELECT unspent_points FROM users WHERE id=$1))
    `, [req.user.id, itemId, qty]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'use_failed', detail: e.message });
  } finally {
    client.release();
  }
});

// ---------- EventSub ----------
function verifyTwitchSignature(req, rawBody) {
  const id = req.header('Twitch-Eventsub-Message-Id') || '';
  const ts = req.header('Twitch-Eventsub-Message-Timestamp') || '';
  const sig = req.header('Twitch-Eventsub-Message-Signature') || ''; // "sha256=..."
  const message = id + ts + rawBody;
  const hmac = crypto.createHmac('sha256', TWITCH_EVENTSUB_SECRET || '');
  const computed = 'sha256=' + hmac.update(message).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(sig));
}

app.post('/eventsub', express.raw({ type: 'application/json' }), async (req, res) => {
  const raw = req.body instanceof Buffer ? req.body.toString('utf8') : (typeof req.body === 'string' ? req.body : '');
  const type = req.header('Twitch-Eventsub-Message-Type') || '';

  if (type === 'webhook_callback_verification') {
    try {
      const payload = JSON.parse(raw);
      return res.status(200).type('text/plain').send(payload.challenge);
    } catch {
      return res.status(400).send('bad_request');
    }
  }

  if (!verifyTwitchSignature(req, raw)) {
    return res.status(403).type('text/plain').send('Invalid signature');
  }

  let payload = null;
  try {
    payload = JSON.parse(raw);
  } catch {
    return res.status(400).send('bad_json');
  }

  if (type === 'notification') {
    const subType = payload.subscription?.type;
    const ev = payload.event || {};

    try {
      const client = await pool.connect();
      await client.query('BEGIN');

      if (subType === 'channel.subscribe') {
        // NEW: non assegnare punti se è un gift ricevuto (recipient)
        const isGift = ev.is_gift === true || ev.is_gift === 1 || ev.is_gift === 'true';
        if (!isGift) {
          const twitch_id = String(ev.user_id || '');
          const username  = ev.user_name || ev.user_login || null;
          if (twitch_id) await grantPointsByTwitchId(client, twitch_id, username, 1);
        }
      } else if (subType === 'channel.subscription.gift') {
        // NEW: assegna punti SOLO al gifter (non anonimo), non ai destinatari
        const isAnon = !!ev.is_anonymous;
        if (!isAnon) {
          const gifter_id   = String(ev.user_id || ev.gifter_user_id || '');
          const gifter_name = ev.user_name || ev.gifter_user_name || ev.user_login || ev.gifter_user_login || null;
          const count = (Number(ev.total) || Number(ev.quantity) || Number(ev.gifts) || 1);
          if (gifter_id) await grantPointsByTwitchId(client, gifter_id, gifter_name, count);
        }
      }

      await client.query('COMMIT');
      client.release();
    } catch (e) {
      console.error('EventSub handler error:', e);
    }
  }

  res.status(200).type('text/plain').send('ok');
});

// ---------- Static ----------
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Server avviato su http://localhost:${PORT}`);
});
