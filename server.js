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
  `);
  return db;
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
function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
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
    userByEmail: db.prepare('SELECT id FROM users WHERE email = ?'),
    // rolul nu vine din cerere, orice cont nou e candidat
    insertUser: db.prepare("INSERT INTO users (id, email, password_hash, email_verified, role) VALUES (?, ?, ?, 1, 'candidate')"),
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
      handler(req, res, await readJson(req));
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
