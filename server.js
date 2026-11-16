import http from 'node:http';
import { readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const INDEX = readFileSync(new URL('./public/index.html', import.meta.url));

// baza de date, tabelele sunt cele din ADMITERE-63 sectiunea 7
export function openDb(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id             TEXT PRIMARY KEY,
      email          TEXT NOT NULL UNIQUE,
      password_hash  TEXT NOT NULL,
      email_verified INTEGER NOT NULL DEFAULT 0,
      role           TEXT NOT NULL DEFAULT 'candidate' CHECK (role IN ('candidate', 'operator', 'admin')),
      created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
  `);
  seedDemo(db);
  return db;
}

// conturile demo din ADMITERE-63 (Candidat, Operator Aurora, Administrator Aurora)
export const DEMO_PASSWORD = 'demo1234';
const DEMO = [['ana@exemplu.demo', 'candidate'], ['operator@aurora.demo', 'operator'], ['admin@aurora.demo', 'admin']];
function seedDemo(db) {
  const add = db.prepare('INSERT INTO users (id, email, password_hash, email_verified, role) VALUES (?, ?, ?, 1, ?)');
  const has = db.prepare('SELECT 1 FROM users WHERE email = ?');
  for (const [email, role] of DEMO) if (!has.get(email)) add.run(randomUUID(), email, hashPassword(DEMO_PASSWORD), role);
}

// parole (scrypt cu salt, nu se salveaza niciodata in clar)
function hashPassword(password) {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${scryptSync(password, salt, 64).toString('hex')}`;
}
export function verifyPassword(password, stored) {
  const [, salt, hash] = stored.split('$');
  return timingSafeEqual(scryptSync(password, Buffer.from(salt, 'hex'), 64), Buffer.from(hash, 'hex'));
}

// validare, mesajele sunt cele din ADMITERE-63
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const str = (v) => (typeof v === 'string' ? v.trim() : '');

function checkEmail(email) {
  if (!email) return 'Introdu adresa de e-mail.';
  if (!EMAIL.test(email) || email.length > 254) return 'Adresa de e-mail nu este validă.';
}

function checkRegister(b) {
  const e = {};
  const email = str(b.email).toLowerCase();
  const m = checkEmail(email);
  if (m) e.email = m;
  if (!b.parola) e.parola = 'Introdu o parolă.';
  else if (typeof b.parola !== 'string' || b.parola.length < 8 || b.parola.length > 200 || !/\p{L}/u.test(b.parola) || !/\d/.test(b.parola))
    e.parola = 'Parola trebuie să aibă cel puțin 8 caractere, o literă și o cifră.';
  if (!b.confirmare) e.confirmare = 'Confirmă parola.';
  else if (b.confirmare !== b.parola) e.confirmare = 'Parolele nu coincid.';
  if (b.termeni !== true) e.termeni = 'Trebuie să accepți Termenii și Politica de confidențialitate.';
  return [email, e];
}

// http
const SESSION_DAYS = 7;
const cookie = (token, maxAge) => `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); }
      catch { reject(new Error('json')); }
    });
  });
}

export function createApp(db) {
  const q = {
    userByEmail: db.prepare('SELECT id, password_hash, role FROM users WHERE email = ?'),
    // rolul nu vine din cerere, orice cont nou e candidat
    insertUser: db.prepare("INSERT INTO users (id, email, password_hash, email_verified, role) VALUES (?, ?, ?, 1, 'candidate')"),
    insertSession: db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
    sessionUser: db.prepare('SELECT u.id, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'),
  };

  // sesiunea e un token random in cookie HttpOnly, salvat in baza de date
  const tokenOf = (req) => /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie ?? '')?.[1];
  const currentUser = (req) => {
    const t = tokenOf(req);
    return t ? q.sessionUser.get(t, Date.now()) : undefined;
  };
  const startSession = (userId) => {
    const token = randomBytes(32).toString('hex');
    q.insertSession.run(token, userId, Date.now() + SESSION_DAYS * 864e5);
    return { 'Set-Cookie': cookie(token, SESSION_DAYS * 86400) };
  };

  const routes = {
    // confirmarea pe e-mail e simulata in demo (ADMITERE-20), contul e confirmat direct
    'POST /api/register': (req, res, b) => {
      const [email, e] = checkRegister(b);
      if (!e.email && q.userByEmail.get(email)) e.email = 'Există deja un cont cu această adresă.';
      if (Object.keys(e).length) return send(res, 400, { erori: e });
      q.insertUser.run(randomUUID(), email, hashPassword(b.parola));
      send(res, 201, { ok: true });
    },
    'POST /api/login': (req, res, b) => {
      const u = q.userByEmail.get(str(b.email).toLowerCase());
      if (!u || typeof b.parola !== 'string' || !verifyPassword(b.parola, u.password_hash))
        return send(res, 401, { eroare: 'E-mailul sau parola sunt incorecte.' });
      send(res, 200, { rol: u.role }, startSession(u.id));
    },
    'POST /api/logout': (req, res) => {
      const t = tokenOf(req);
      if (t) q.deleteSession.run(t);
      send(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
    },
    // cine e logat, de aici interfata stie ce sa arate
    'GET /api/me': (req, res) => {
      const u = currentUser(req);
      if (!u) return send(res, 401, { eroare: 'Trebuie să te autentifici.' });
      send(res, 200, { email: u.email, rol: u.role });
    },
  };

  return async (req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    if (req.method === 'GET' && path === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(INDEX);
    }
    const handler = routes[`${req.method} ${path}`];
    if (!handler) return send(res, 404, { eroare: 'Pagina nu există.' });
    try {
      handler(req, res, req.method === 'GET' ? {} : await readJson(req));
    } catch {
      send(res, 400, { eroare: 'Cerere invalidă.' });
    }
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  const db = openDb(process.env.ADMITERE_DB ?? 'data/roadmitere.db');
  http.createServer(createApp(db)).listen(port, '127.0.0.1', () => console.log(`RoAdmitere pornit: http://localhost:${port}`));
}
