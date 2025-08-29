// server.js
require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const TwitchStrategy = require('passport-twitch-new').Strategy;
const { Pool } = require('pg');

const app = express();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://malgax.com',
  'https://www.malgax.com',
  'https://api.malgax.com',
];

app.set('trust proxy', 1);
app.use(cors({ origin: ORIGINS, credentials: true }));
app.use(cookieParser());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      twitch_id TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      total_points INTEGER NOT NULL DEFAULT 0,
      unspent_points INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS point_transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      delta_points INTEGER NOT NULL,
      points_before INTEGER NOT NULL,
      points_after INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS shop_items (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      kind TEXT NOT NULL,
      cost_points INTEGER NOT NULL,
      image_url TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS inventory (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      item_id INTEGER NOT NULL REFERENCES shop_items(id) ON DELETE CASCADE,
      quantity INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, item_id)
    );
  `);
}

const sessionOpts = {
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    secure: NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 30,
  },
};
app.use(session(sessionOpts));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, twitch_id, username, total_points, unspent_points FROM users WHERE id = $1`,
      [id]
    );
    if (rows.length) return done(null, rows[0]);
    return done(null, false);
  } catch (e) {
    return done(e);
  }
});

const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID;
const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET;
const TWITCH_CALLBACK_URL =
  process.env.TWITCH_CALLBACK_URL ||
  process.env.CALLBACK_URL ||
  'http://localhost:3000/auth/twitch/callback';

passport.use(new TwitchStrategy({
  clientID: TWITCH_CLIENT_ID,
  clientSecret: TWITCH_CLIENT_SECRET,
  callbackURL: TWITCH_CALLBACK_URL,
  scope: ['user:read:email', 'channel:read:subscriptions'],
  passReqToCallback: true,
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const twitchId = profile.id;
    const username = profile.display_name || profile.username || `user_${twitchId}`;
    const up = await pool.query(`
      INSERT INTO users (twitch_id, username)
      VALUES ($1, $2)
      ON CONFLICT (twitch_id)
      DO UPDATE SET username = EXCLUDED.username, updated_at = NOW()
      RETURNING id, twitch_id, username, total_points, unspent_points
    `, [twitchId, username]);
    return done(null, up.rows[0]);
  } catch (e) {
    return done(e);
  }
}));

app.get('/auth/twitch', (req, res, next) => {
  passport.authenticate('twitch', { state: 'login' })(req, res, next);
});

app.get('/auth/twitch/callback',
  passport.authenticate('twitch', { failureRedirect: '/auth-failed.html' }),
  (req, res) => {
    const origin = (req.headers.referer && new URL(req.headers.referer).origin) || '*';
    res.status(200).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Login OK</title></head>
<body style="background:#0f0f14;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh">
<div>✅ Login effettuato. Puoi chiudere questa finestra.</div>
<script>
  try { if (window.opener) { window.opener.postMessage({ type: 'login' }, '${origin}'); window.close(); } } catch(_) {}
</script>
</body></html>`);
  }
);

app.get('/logout', (req, res) => {
  const origin = (req.headers.referer && new URL(req.headers.referer).origin) || '*';
  const send = () => {
    res.status(200).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Logout</title></head>
<body style="background:#0f0f14;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh">
<div>👋 Logout eseguito. Puoi chiudere questa finestra.</div>
<script>
  try { if (window.opener) { window.opener.postMessage({ type: 'logout' }, '${origin}'); window.close(); } } catch(_) {}
</script>
</body></html>`);
  };
  if (req.logout) { req.logout(() => req.session?.destroy(()=> send())); }
  else { req.session?.destroy(()=> send()); }
});

app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  res.json(req.user);
});

app.get('/api/leaderboard/top', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT username, total_points AS points
      FROM users
      WHERE total_points > 0
      ORDER BY total_points DESC, username ASC
      LIMIT 100
    `);
    res.json(rows);
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/leaderboard/unspent', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT username, unspent_points AS points
      FROM users
      WHERE unspent_points > 0
      ORDER BY unspent_points DESC, username ASC
      LIMIT 100
    `);
    res.json(rows);
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server_error' });
  }
});

app.get('/shop/items', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, name, kind, cost_points, image_url
      FROM shop_items
      WHERE active = TRUE
      ORDER BY id ASC
    `);
    res.json(rows);
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server_error' });
  }
});

app.post('/shop/purchase', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  const userId = req.user.id;
  const { item_id, quantity } = req.body;
  const qty = Math.max(1, Number(quantity || 1));

  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const it = await client.query(
        `SELECT id, name, cost_points FROM shop_items WHERE id = $1 AND active = TRUE`,
        [item_id]
      );
      if (it.rowCount === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'item_not_found' }); }
      const item = it.rows[0];
      const totalCost = item.cost_points * qty;

      const u = await client.query(
        `SELECT id, unspent_points FROM users WHERE id = $1 FOR UPDATE`,
        [userId]
      );
      if (u.rowCount === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'user_not_found' }); }
      const beforePts = Number(u.rows[0].unspent_points) || 0;
      if (beforePts < totalCost) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'insufficient_points' }); }

      const u2 = await client.query(
        `UPDATE users
           SET unspent_points = unspent_points - $2,
               updated_at = NOW()
         WHERE id = $1
         RETURNING unspent_points`,
        [userId, totalCost]
      );
      const afterPts = Number(u2.rows[0].unspent_points) || 0;

      await client.query(
        `INSERT INTO inventory (user_id, item_id, quantity)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, item_id)
         DO UPDATE SET quantity = inventory.quantity + EXCLUDED.quantity,
                       updated_at = NOW()`,
        [userId, item_id, qty]
      );

      await client.query(
        `INSERT INTO point_transactions (user_id, type, delta_points, points_before, points_after)
         VALUES ($1, 'spend', $2, $3, $4)`,
        [userId, -totalCost, beforePts, afterPts]
      );

      await client.query('COMMIT');
      res.json({ ok: true, unspent_after: afterPts });
    } catch (e) {
      await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'server_error' });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server_error' });
  }
});

// INVENTORY — filtra quantità 0 e disabilita cache
app.get('/inventory', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  const userId = req.user.id;
  try {
    const { rows } = await pool.query(
      `SELECT i.item_id, i.quantity, s.name, s.image_url
         FROM inventory i
         JOIN shop_items s ON s.id = i.item_id
        WHERE i.user_id = $1
          AND i.quantity IS NOT NULL
          AND i.quantity >= 1
        ORDER BY s.name ASC`,
      [userId]
    );
    res.set('Cache-Control', 'no-store');
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// USE item — elimina la riga se arriva a 0
app.post('/inventory/use', async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  const userId = req.user.id;
  const { item_id, quantity } = req.body;
  const qty = Math.max(1, Number(quantity || 1));

  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const cur = await client.query(
        `SELECT id, quantity FROM inventory
         WHERE user_id = $1 AND item_id = $2
         FOR UPDATE`,
        [userId, item_id]
      );
      if (cur.rowCount === 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'not_in_inventory' }); }

      const invId = cur.rows[0].id;
      const have = Number(cur.rows[0].quantity) || 0;
      if (have < qty) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'not_enough_quantity' }); }

      const remaining = have - qty;
      if (remaining <= 0) {
        await client.query(`DELETE FROM inventory WHERE id = $1`, [invId]);
        await client.query('COMMIT');
        return res.json({ ok: true, remaining: 0, deleted: true });
      } else {
        await client.query(
          `UPDATE inventory
             SET quantity = $2,
                 updated_at = NOW()
           WHERE id = $1`,
          [invId, remaining]
        );
        await client.query('COMMIT');
        return res.json({ ok: true, remaining });
      }
    } catch (e) {
      await client.query('ROLLBACK'); console.error(e); return res.status(500).json({ error: 'server_error' });
    } finally {
      client.release();
    }
  } catch (e) {
    console.error(e); return res.status(500).json({ error: 'server_error' });
  }
});

// EventSub
const EVENTSUB_SECRET = process.env.TWITCH_EVENTSUB_SECRET || 'set-me';
function timingSafeEqual(a, b) {
  const ba = Buffer.from(a); const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

app.post('/eventsub', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const messageId = req.get('Twitch-Eventsub-Message-Id') || '';
    const timestamp = req.get('Twitch-Eventsub-Message-Timestamp') || '';
    const signature = req.get('Twitch-Eventsub-Message-Signature') || '';
    const messageType = req.get('Twitch-Eventsub-Message-Type') || '';
    const rawBody = req.body instanceof Buffer ? req.body.toString('utf8') : String(req.body || '');
    const expected = 'sha256=' + crypto.createHmac('sha256', EVENTSUB_SECRET).update(messageId + timestamp + rawBody).digest('hex');

    if (!timingSafeEqual(signature, expected)) {
      return res.status(403).type('text/plain').send('Invalid signature');
    }

    const payload = rawBody ? JSON.parse(rawBody) : {};
    if (messageType === 'webhook_callback_verification') {
      return res.status(200).type('text/plain').send(payload.challenge);
    }

    if (messageType === 'notification') {
      const subType = payload.subscription?.type;
      const ev = payload.event || {};

      if (subType === 'channel.subscribe') {
        const twitchId = ev.user_id;
        const username = ev.user_login || ev.user_name || ('user_'+twitchId);
        await grantPointsToTwitchUser(twitchId, username, 1);
      }

      if (subType === 'channel.subscription.gift') {
        const twitchId = ev.user_id;
        const username = ev.user_login || ev.user_name || ('user_'+twitchId);
        const n = Number(ev.total) || 1;
        await grantPointsToTwitchUser(twitchId, username, n);
      }

      return res.status(200).json({ ok: true });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('eventsub error:', e);
    return res.status(500).type('text/plain').send('server_error');
  }
});

async function grantPointsToTwitchUser(twitchId, username, delta) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const up = await client.query(`
      INSERT INTO users (twitch_id, username)
      VALUES ($1, $2)
      ON CONFLICT (twitch_id)
      DO UPDATE SET username = EXCLUDED.username, updated_at = NOW()
      RETURNING id, total_points, unspent_points
    `, [twitchId, username]);

    const userId = up.rows[0].id;
    const before = Number(up.rows[0].unspent_points) || 0;

    const upd = await client.query(`
      UPDATE users
         SET total_points   = total_points + $2,
             unspent_points = unspent_points + $2,
             updated_at     = NOW()
       WHERE id = $1
       RETURNING unspent_points
    `, [userId, delta]);

    const after = Number(upd.rows[0].unspent_points) || (before + delta);

    await client.query(`
      INSERT INTO point_transactions (user_id, type, delta_points, points_before, points_after)
      VALUES ($1, 'grant', $2, $3, $4)
    `, [userId, delta, before, after]);

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('grantPoints error:', e);
  } finally {
    client.release();
  }
}

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/_routes', (_req, res) => {
  const list = [];
  const stack = app._router && app._router.stack || [];
  stack.forEach((m) => {
    if (m.route && m.route.path) {
      const methods = Object.keys(m.route.methods).filter(k => m.route.methods[k]).map(k => k.toUpperCase());
      list.push({ path: m.route.path, methods });
    } else if (m.name === 'router' && m.handle && m.handle.stack) {
      m.handle.stack.forEach((h) => {
        if (h.route && h.route.path) {
          const methods = Object.keys(h.route.methods).filter(k => h.route.methods[k]).map(k => k.toUpperCase());
          list.push({ path: h.route.path, methods });
        }
      });
    }
  });
  res.json(list);
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', extensions: ['html'] }));
app.get('/leaderboard/top', (_req, res) => res.redirect(301, '/api/leaderboard/top'));
app.get('/leaderboard/unspent', (_req, res) => res.redirect(301, '/api/leaderboard/unspent'));
app.get('/leaderboard', (_req, res) => res.redirect(301, '/leaderboard.html'));

ensureTables().then(() => {
  app.listen(PORT, () => console.log(`Server avviato su http://localhost:${PORT}.`));
}).catch(e => { console.error('DB init error:', e); process.exit(1); });
