require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- config ----
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '2008'; // fixed owner login password
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- tiny JSON "database" for signed-up users ----
// We only ever store what Google gives us about the account (email, name,
// picture, Google's internal id). We never see or store a Google password —
// Google never sends it to us. There is no password field for regular users.
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function upsertUser({ googleId, email, name, picture }) {
  const users = loadUsers();
  const existing = users.find((u) => u.googleId === googleId);
  const now = new Date().toISOString();
  if (existing) {
    existing.name = name;
    existing.picture = picture;
    existing.lastLoginAt = now;
    saveUsers(users);
    return existing;
  }
  const user = { googleId, email, name, picture, createdAt: now, lastLoginAt: now };
  users.push(user);
  saveUsers(users);
  return user;
}

// ---- auth helpers ----
function issueSessionCookie(res, payload, { expiresIn = '7d' } = {}) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn });
  res.cookie('session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not signed in' });
  try {
    req.session = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired' });
  }
}

function requireAdmin(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not signed in' });
  try {
    const session = jwt.verify(token, JWT_SECRET);
    if (session.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.session = session;
    next();
  } catch {
    res.status(401).json({ error: 'Session expired' });
  }
}

// ---- routes ----

// Frontend fetches the Google Client ID from here rather than it being
// baked into the HTML, so it's easy to swap without editing the page.
app.get('/api/config', (req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID });
});

// Real "Sign in / up with Google". The browser's Google Identity Services
// widget handles the actual login on Google's own domain and hands us a
// signed ID token. We verify that token with Google, then read the
// account's email/name/picture out of it. Nobody's password ever passes
// through this server — Google doesn't send it, so we can't log it even
// by accident.
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: 'Missing credential' });
  if (!GOOGLE_CLIENT_ID) {
    return res.status(500).json({ error: 'Server is missing GOOGLE_CLIENT_ID configuration' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    const user = upsertUser({
      googleId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    });

    issueSessionCookie(res, { role: 'user', googleId: user.googleId, email: user.email });
    res.json({ user: { email: user.email, name: user.name, picture: user.picture } });
  } catch (err) {
    console.error('Google sign-in failed:', err.message);
    res.status(401).json({ error: 'Could not verify Google sign-in' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ session: req.session });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

// Fixed owner/admin login — a single account, not tied to any email
// provider. Password is set via ADMIN_PASSWORD env var (defaults to the
// one requested: 2008). Change it in production by setting the env var.
app.post('/api/auth/admin', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Incorrect password' });
  }
  issueSessionCookie(res, { role: 'admin' }, { expiresIn: '12h' });
  res.json({ ok: true });
});

// Admin-only: list everyone who has signed up with Google. No passwords
// are ever stored or returned here — there aren't any to show.
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers().map((u) => ({
    email: u.email,
    name: u.name,
    picture: u.picture,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt,
  }));
  res.json({ users });
});

app.listen(PORT, () => {
  console.log(`Braintech Orbit backend running on http://localhost:${PORT}`);
});
