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
      failed_logins  INTEGER NOT NULL DEFAULT 0,
      locked_until   INTEGER NOT NULL DEFAULT 0,
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

function checkLogin(b) {
  const e = {};
  const email = str(b.email).toLowerCase();
  const m = checkEmail(email);
  if (m) e.email = m;
  if (!b.parola || typeof b.parola !== 'string') e.parola = 'Introdu parola.';
  return [email, e];
}

// http
const SESSION_DAYS = 7;
const MAX_TRIES = 5;
const LOCK_MINUTES = 15;
const MAX_BODY = 10_000;
const cookie = (token, maxAge) => `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
// no-store ca dupa logout butonul Back sa nu mai arate pagina din cache (ADMITERE-81 TC-06)
const NO_CACHE = { 'Cache-Control': 'no-store' };

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...NO_CACHE, ...headers });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    // daca e prea mare nu mai pastram nimic, dar citim pana la capat ca sa putem raspunde
    req.on('data', (c) => {
      size += c.length;
      if (size <= MAX_BODY) chunks.push(c);
    });
    req.on('end', () => {
      if (size > MAX_BODY) return reject(Object.assign(new Error('prea mare'), { status: 413 }));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); }
      catch { reject(Object.assign(new Error('json'), { status: 400 })); }
    });
  });
}

// hash fals, ca un e-mail inexistent sa dureze cat unul existent
const DUMMY_HASH = hashPassword('nu-exista-1');

export function createApp(db) {
  const q = {
    userByEmail: db.prepare('SELECT id, password_hash, role, failed_logins, locked_until FROM users WHERE email = ?'),
    setFails: db.prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?'),
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
      const [email, e] = checkLogin(b);
      if (Object.keys(e).length) return send(res, 400, { erori: e });
      const u = q.userByEmail.get(email);
      const now = Date.now();
      const locked = { eroare: `Prea multe încercări. Încearcă din nou peste ${LOCK_MINUTES} minute.` };
      if (u && u.locked_until > now) return send(res, 429, locked);
      if (!verifyPassword(b.parola, u?.password_hash ?? DUMMY_HASH) || !u) {
        // dupa 5 greseli la rand contul se blocheaza 15 minute (ADMITERE-63)
        if (u) {
          const n = u.failed_logins + 1;
          if (n >= MAX_TRIES) { q.setFails.run(0, now + LOCK_MINUTES * 60_000, u.id); return send(res, 429, locked); }
          q.setFails.run(n, 0, u.id);
        }
        return send(res, 401, { eroare: 'E-mailul sau parola sunt incorecte.' });
      }
      q.setFails.run(0, 0, u.id);
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
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...NO_CACHE });
      return res.end(INDEX);
    }
    const handler = routes[`${req.method} ${path}`];
    // raspuns scurt, fara detalii despre ce exista pe server (ADMITERE-53)
    if (!handler) return send(res, 404, { eroare: 'Pagina nu există.' });
    try {
      let body = {};
      if (req.method !== 'GET') {
        // doar json, ca sa nu poata trimite alt site formulare in numele userului
        if (!req.headers['content-type']?.startsWith('application/json')) return send(res, 415, { eroare: 'Cerere invalidă.' });
        body = await readJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body)) return send(res, 400, { eroare: 'Cerere invalidă.' });
      }
      handler(req, res, body);
    } catch (err) {
      if (err.status) return send(res, err.status, { eroare: 'Cerere invalidă.' });
      console.error(err.message);
      send(res, 500, { eroare: 'A apărut o eroare. Încearcă din nou.' });
    }
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  const db = openDb(process.env.ADMITERE_DB ?? 'data/roadmitere.db');
  http.createServer(createApp(db)).listen(port, '127.0.0.1', () => console.log(`RoAdmitere pornit: http://localhost:${port}`));
}
