require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const TwitchStrategy = require('passport-twitch-new').Strategy;
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Se hai un proxy davanti (Render/Ngrok), puoi abilitare:
// app.set('trust proxy', 1);

// ========== DB ==========
const db = new sqlite3.Database(process.env.DB_PATH || './db.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    twitch_id TEXT UNIQUE,
    username TEXT,
    points INTEGER DEFAULT 0
  )`);
});

// ========== Sessioni & Passport ==========
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  // cookie: { secure: true, sameSite: 'lax' } // usa secure:true solo con HTTPS end-to-end
}));
app.use(passport.initialize());
app.use(passport.session());

// ========== OAuth Twitch ==========
passport.use(new TwitchStrategy(
  {
    clientID: process.env.TWITCH_CLIENT_ID,
    clientSecret: process.env.TWITCH_CLIENT_SECRET,
    callbackURL: process.env.TWITCH_CALLBACK_URL,
    scope: 'user:read:email channel:read:subscriptions'
  },
  (accessToken, refreshToken, profile, done) => {
    db.run(
      `INSERT OR IGNORE INTO users (twitch_id, username, points) VALUES (?, ?, 0)`,
      [profile.id, profile.display_name],
      (err) => {
        if (err) return done(err);
        db.get(`SELECT * FROM users WHERE twitch_id = ?`, [profile.id], (err2, row) => {
          done(err2, row);
        });
      }
    );
  }
));
passport.serializeUser((user, done) => done(null, user.twitch_id));
passport.deserializeUser((id, done) => {
  db.get(`SELECT * FROM users WHERE twitch_id = ?`, [id], (err, row) => done(err, row));
});

// ========== Body parsers ==========
app.use('/eventsub', express.raw({ type: 'application/json' })); // RAW solo per EventSub (firma HMAC)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ========== Static ==========
app.use(express.static(path.join(__dirname, 'public')));

// ========== Rotte OAuth ==========
app.get('/auth/twitch',
  (req, res, next) => {
    // conserva l'informazione se il login è partito da un popup
    if (req.query.popup === '1') req.session.oauthPopup = '1';
    next();
  },
  passport.authenticate('twitch')
);

app.get('/auth/twitch/callback',
  passport.authenticate('twitch', { failureRedirect: '/' }),
  (req, res) => {
    const isPopup = req.session.oauthPopup === '1' || req.query.popup === '1';
    delete req.session.oauthPopup;
    res.redirect(isPopup ? '/profile.html?popup=1' : '/profile.html');
  }
);

// ========== Logout “crash-proof” (chiude popup SEMPRE) ==========
app.get('/logout', (req, res) => {
  const isPopup = req.query.popup === '1';

  const sendPopupClose = () => {
    // Risposta HTML che invia postMessage e chiude la finestra SEMPRE, anche se ci sono errori lato server
    res.status(200).type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Logout</title></head>
<body style="background:#0f0f14;color:#f4f4f7;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh">
  <div>Logout effettuato. Puoi chiudere questa finestra.</div>
  <script>
    (function(){
      try {
        if (window.opener) {
          window.opener.postMessage({ type: 'logout' }, 'https://www.malgax.com');
          window.opener.postMessage({ type: 'logout' }, 'https://malgax.com');
        }
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: 'logout' }, 'https://www.malgax.com');
          window.parent.postMessage({ type: 'logout' }, 'https://malgax.com');
        }
      } catch (e) {}
      // tenta di chiudere subito
      try { window.close(); } catch(e) {}
      // fallback: svuota la pagina, così non si vede l'errore del server
      setTimeout(function(){
        try { document.body.innerHTML = '<div style="color:#9aa0a6">Logout completato. Puoi chiudere questa finestra.</div>'; } catch(e){}
      }, 0);
    })();
  </script>
</body></html>`);
  };

  const finish = () => {
    if (isPopup) return sendPopupClose();
    // non popup: torna alla home
    return res.redirect('/');
  };

  // logout compatibile con Passport 0.6+ e versioni precedenti
  const doLogout = (cb) => {
    try {
      if (typeof req.logout === 'function') {
        if (req.logout.length > 0) {
          // Passport >= 0.6 richiede callback
          return req.logout(() => cb());
        } else {
          // Passport < 0.6
          req.logout();
          return cb();
        }
      }
      return cb();
    } catch (e) {
      // ignora errori di logout e continua
      return cb();
    }
  };

  const destroySession = (cb) => {
    try {
      if (req.session) return req.session.destroy(() => cb());
    } catch (e) { /* ignore */ }
    cb();
  };

  doLogout(() => destroySession(finish));
});

// ========== API ==========
app.get('/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Non autenticato' });
  res.json(req.user);
});

app.get('/leaderboard', (req, res) => {
  db.all(`SELECT username, points FROM users ORDER BY points DESC, username ASC LIMIT 100`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ========== EventSub ==========
app.post('/eventsub', (req, res) => {
  const secret = process.env.TWITCH_EVENTSUB_SECRET || '';
  const msgId = req.get('Twitch-Eventsub-Message-Id') || '';
  const timestamp = req.get('Twitch-Eventsub-Message-Timestamp') || '';
  const signature = (req.get('Twitch-Eventsub-Message-Signature') || '').toLowerCase();

  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(msgId);
  hmac.update(timestamp);
  hmac.update(req.body); // Buffer RAW
  const expected = 'sha256=' + hmac.digest('hex');

  if (expected !== signature) {
    return res.status(403).type('text/plain').send('Invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString('utf8'));
  } catch (e) {
    return res.status(400).type('text/plain').send('Bad JSON');
  }

  if (payload.challenge) {
    return res.status(200).type('text/plain').send(payload.challenge);
  }

  const { subscription, event } = payload;
  if (!subscription || !event) return res.sendStatus(200);

  if (subscription.type === 'channel.subscribe') {
    db.run(
      `INSERT INTO users (twitch_id, username, points)
       VALUES (?, ?, 1)
       ON CONFLICT(twitch_id) DO UPDATE SET points = points + 1`,
      [event.user_id, event.user_name]
    );
  }

  if (subscription.type === 'channel.subscription.gift') {
    const giftCount = Number(event.total) || 1;
    db.run(
      `INSERT INTO users (twitch_id, username, points)
       VALUES (?, ?, ?)
       ON CONFLICT(twitch_id) DO UPDATE SET points = points + ?`,
      [event.user_id, event.user_name, giftCount, giftCount]
    );
  }

  return res.sendStatus(200);
});

// ========== Health ==========
app.get('/health', (req, res) => res.send('OK'));

// ========== Start ==========
app.listen(PORT, () => {
  console.log(`Server avviato su http://localhost:${PORT}`);
});
