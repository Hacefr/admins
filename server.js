const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('./staffboard.db');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'mc-staff-discord-secret-999',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

// Initialize Database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT,
    user_id INTEGER,
    username TEXT,
    role TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Initial silent seed: user 'owner' with 'admin123' if no users exist
  db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
    if (row && row.count === 0) {
      const hashed = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO users (username, password, role) VALUES ('owner', ?, 'owner')`, [hashed]);
    }
  });
});

// Guard Middleware
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function requireOwner(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'owner') {
    return res.status(403).json({ error: 'Forbidden: Owner only' });
  }
  next();
}

// Channel access rules
function canAccessChannel(role, channel) {
  if (role === 'owner') return true;
  if (channel === 'announcements' || channel === 'general-staff') return true;
  if (channel === 'mod-enforcement' && role === 'moderator') return true;
  if (channel === 'tester-lab' && role === 'tester') return true;
  return false;
}

// --- AUTH ROUTES ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.json({ success: true, user: req.session.user });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/session', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// --- MESSAGING ---
app.get('/api/messages/:channel', requireAuth, (req, res) => {
  const { channel } = req.params;
  const role = req.session.user.role;

  if (!canAccessChannel(role, channel)) {
    return res.status(403).json({ error: 'Access denied to this channel' });
  }

  db.all(
    `SELECT * FROM messages WHERE channel = ? ORDER BY id ASC LIMIT 100`,
    [channel],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database read error' });
      res.json(rows || []);
    }
  );
});

app.post('/api/messages/:channel', requireAuth, (req, res) => {
  const { channel } = req.params;
  const { content } = req.body;
  const { id, username, role } = req.session.user;

  if (!canAccessChannel(role, channel)) {
    return res.status(403).json({ error: 'Access denied to this channel' });
  }

  // Only owner can post in announcements
  if (channel === 'announcements' && role !== 'owner') {
    return res.status(403).json({ error: 'Only the owner can post announcements' });
  }

  if (!content || !content.trim()) return res.status(400).json({ error: 'Empty message' });

  db.run(
    `INSERT INTO messages (channel, user_id, username, role, content) VALUES (?, ?, ?, ?, ?)`,
    [channel, id, username, role, content.trim()],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to post message' });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// --- STAFF ROSTER ---
app.get('/api/roster', requireAuth, (req, res) => {
  db.all(`SELECT id, username, role FROM users ORDER BY username ASC`, (err, rows) => {
    res.json(rows || []);
  });
});

// --- OWNER CONTROLS ---
app.post('/api/owner/users', requireOwner, (req, res) => {
  const { username, password, role } = req.body;
  const allowed = ['tester', 'helper', 'moderator', 'owner'];
  if (!username || !password || !allowed.includes(role)) {
    return res.status(400).json({ error: 'Invalid staff details' });
  }
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashed, role], function(err) {
    if (err) return res.status(400).json({ error: 'Username already in use' });
    res.json({ success: true, id: this.lastID });
  });
});

app.delete('/api/owner/users/:id', requireOwner, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId === req.session.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  db.run(`DELETE FROM users WHERE id = ?`, [targetId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to delete' });
    res.json({ success: true });
  });
});

app.post('/api/owner/change-password', requireOwner, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 5) {
    return res.status(400).json({ error: 'Password must be at least 5 characters' });
  }
  const hashed = bcrypt.hashSync(newPassword, 10);
  db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashed, req.session.user.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update' });
    res.json({ success: true });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Staff Message Board online on port ${PORT}`));
