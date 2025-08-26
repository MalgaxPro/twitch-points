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

// --- DB: crea tabella se non esiste ---
const db = new sqlite3.Database('./db.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    twitch_id TEXT UNIQUE,
    username TEXT,
    points INTEGER DEFAULT 0
  )`);
});

// --- Sessioni & Passport ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// --- Strategia Twitch (OAuth) ---
passport.use(new TwitchStrategy(
  {
    clientID: process.env.TWITCH_CLIENT_ID,
    clientSecret: process.env.TWITCH_CLIENT_SECRET,
    callbackURL: process.env.TWITCH_CALLBACK_URL,
    scope: 'user:read:email channel:read:subscriptions'
  },
  (accessToken, refreshToken, profile, done) => {
    // crea utente se non esiste, altrimenti restituiscilo
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

// === IMPORTANTISSIMO per EventSub: leggere RAW body su /eventsub ===
app.use('/eventsub', express.raw({ type: 'application/json' }));

// Per il resto dell’app (JSON normale + static)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Rotte OAuth ---
app.get('/auth/twitch', passport.authenticate('twitch'));

app.get('/auth/twitch/callback',
  passport.authenticate('twitch', { failureRedirect: '/' }),
  (req, res) => res.redirect('/profile.html')
);

// --- API ---
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

// --- EventSub webhook ---
app.post('/eventsub', (req, res) => {
  const secret = process.env.TWITCH_EVENTSUB_SECRET || '';
  const msgId = req.get('Twitch-Eventsub-Message-Id') || '';
  const timestamp = req.get('Twitch-Eventsub-Message-Timestamp') || '';
  const signature = (req.get('Twitch-Eventsub-Message-Signature') || '').toLowerCase();

  // req.body è un Buffer (grazie a express.raw su /eventsub)
  // Calcolo HMAC in modo binary-safe: msgId || timestamp || rawBody
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(msgId);
  hmac.update(timestamp);
  hmac.update(req.body);
  const expected = 'sha256=' + hmac.digest('hex');

  if (expected !== signature) {
    return res.status(403).type('text/plain').send('Invalid signature');
  }

  // Challenge di verifica (risposta in text/plain)
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

// --- Avvio ---
app.get('/health', (req, res) => res.send('OK'));
app.listen(PORT, () => {
  console.log(`Server avviato su http://localhost:${PORT}`);
});
