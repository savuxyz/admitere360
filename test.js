// teste pt ADMITERE-49, dupa cazurile din ADMITERE-63 (sectiunea 8), ADMITERE-81 si ADMITERE-53
// rulare: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { openDb, createApp } from './server.js';

const db = openDb(':memory:');
const server = http.createServer(createApp(db)).listen(0);
const base = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

async function call(method, path, data) {
  const r = await fetch(base + path, { method, headers: data ? { 'Content-Type': 'application/json' } : {}, body: data && JSON.stringify(data) });
  return { status: r.status, body: await r.json().catch(() => null) };
}

const cont = (email, parola = 'parola123') => ({ email, parola, confirmare: parola, termeni: true });

test('ADMITERE-68: cont nou cu date valide', async () => {
  const r = await call('POST', '/api/register', cont('ana.pop@exemplu.demo'));
  assert.equal(r.status, 201);
  const u = db.prepare('SELECT role, email_verified, password_hash FROM users WHERE email = ?').get('ana.pop@exemplu.demo');
  assert.equal(u.role, 'candidate');
  assert.equal(u.email_verified, 1);
  assert.ok(!u.password_hash.includes('parola123'));
});

test('ADMITERE-68: acelasi e-mail nu face al doilea cont', async () => {
  await call('POST', '/api/register', cont('dublu@exemplu.demo'));
  const r = await call('POST', '/api/register', cont('DUBLU@exemplu.demo'));
  assert.equal(r.status, 400);
  assert.equal(r.body.erori.email, 'Există deja un cont cu această adresă.');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM users WHERE email = ?').get('dublu@exemplu.demo').n, 1);
});

test('ADMITERE-68: campuri lipsa si gresite', async () => {
  let r = await call('POST', '/api/register', {});
  assert.deepEqual(r.body.erori, {
    email: 'Introdu adresa de e-mail.',
    parola: 'Introdu o parolă.',
    confirmare: 'Confirmă parola.',
    termeni: 'Trebuie să accepți Termenii și Politica de confidențialitate.',
  });
  r = await call('POST', '/api/register', { email: 'ana@', parola: 'abc', confirmare: 'abd', termeni: true });
  assert.equal(r.body.erori.email, 'Adresa de e-mail nu este validă.');
  assert.equal(r.body.erori.parola, 'Parola trebuie să aibă cel puțin 8 caractere, o literă și o cifră.');
  assert.equal(r.body.erori.confirmare, 'Parolele nu coincid.');
  r = await call('POST', '/api/register', cont('cifre@exemplu.demo', '12345678'));
  assert.ok(r.body.erori.parola);
});

test('ADMITERE-68: rolul nu se poate alege din cerere', async () => {
  await call('POST', '/api/register', { ...cont('hacker@exemplu.demo'), role: 'admin', rol: 'admin' });
  assert.equal(db.prepare('SELECT role FROM users WHERE email = ?').get('hacker@exemplu.demo').role, 'candidate');
});

// pastreaza cookie-ul de sesiune intre cereri, ca un browser
async function as(sid, method, path, data) {
  const headers = sid ? { Cookie: sid } : {};
  if (data) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + path, { method, headers, body: data && JSON.stringify(data) });
  return { status: r.status, body: await r.json().catch(() => null), sid: r.headers.get('set-cookie')?.split(';')[0] };
}

test('ADMITERE-69: parola gresita nu intra', async () => {
  const r = await call('POST', '/api/login', { email: 'ana@exemplu.demo', parola: 'gresita123' });
  assert.equal(r.status, 401);
  assert.equal(r.body.eroare, 'E-mailul sau parola sunt incorecte.');
  const r2 = await call('POST', '/api/login', { email: 'nimeni@exemplu.demo', parola: 'gresita123' });
  assert.deepEqual(r2.body, r.body);
});

test('ADMITERE-69: conturile demo intra si ajung la rolul lor', async () => {
  for (const [email, rol] of [['ana@exemplu.demo', 'candidate'], ['operator@aurora.demo', 'operator'], ['admin@aurora.demo', 'admin']]) {
    const { status, sid } = await as(null, 'POST', '/api/login', { email, parola: 'demo1234' });
    assert.equal(status, 200);
    const me = await as(sid, 'GET', '/api/me');
    assert.deepEqual(me.body, { email, rol });
  }
});

test('ADMITERE-69: cont nou -> login -> logout inchide accesul', async () => {
  await call('POST', '/api/register', cont('ion@exemplu.demo'));
  const { sid } = await as(null, 'POST', '/api/login', { email: 'ION@exemplu.demo', parola: 'parola123' });
  assert.match(sid, /^sid=[a-f0-9]{64}$/);
  assert.equal((await as(sid, 'GET', '/api/me')).status, 200);
  await as(sid, 'POST', '/api/logout', {});
  assert.equal((await as(sid, 'GET', '/api/me')).status, 401);
});

test('ADMITERE-69: fara login nu ai acces', async () => {
  assert.equal((await call('GET', '/api/me')).status, 401);
  assert.equal((await as('sid=' + 'a'.repeat(64), 'GET', '/api/me')).status, 401);
});

test('ADMITERE-70: mesaje la login cu campuri lipsa sau gresite', async () => {
  let r = await call('POST', '/api/login', {});
  assert.deepEqual(r.body.erori, { email: 'Introdu adresa de e-mail.', parola: 'Introdu parola.' });
  r = await call('POST', '/api/login', { email: 'ana@', parola: 'x' });
  assert.equal(r.body.erori.email, 'Adresa de e-mail nu este validă.');
});

test('ADMITERE-70: dupa 5 parole gresite contul se blocheaza 15 minute', async () => {
  await call('POST', '/api/register', cont('blocat@exemplu.demo'));
  const gresit = { email: 'blocat@exemplu.demo', parola: 'gresita123' };
  for (let i = 1; i <= 4; i++) assert.equal((await call('POST', '/api/login', gresit)).status, 401);
  const r = await call('POST', '/api/login', gresit);
  assert.equal(r.status, 429);
  assert.equal(r.body.eroare, 'Prea multe încercări. Încearcă din nou peste 15 minute.');
  // nici parola buna nu merge cat e blocat
  assert.equal((await call('POST', '/api/login', { ...gresit, parola: 'parola123' })).status, 429);
  // dupa 15 minute merge iar
  db.prepare('UPDATE users SET locked_until = 0 WHERE email = ?').run('blocat@exemplu.demo');
  assert.equal((await call('POST', '/api/login', { ...gresit, parola: 'parola123' })).status, 200);
});

test('ADMITERE-70: paginile nu raman in cache dupa logout', async () => {
  for (const p of ['/', '/api/me']) assert.equal((await fetch(base + p)).headers.get('cache-control'), 'no-store');
});

test('ADMITERE-70: cereri ciudate primesc raspuns scurt, fara detalii', async () => {
  let r = await fetch(base + '/api/login', { method: 'POST', body: 'email=a&parola=b', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  assert.equal(r.status, 415);
  r = await fetch(base + '/api/login', { method: 'POST', body: '{nu e json', headers: { 'Content-Type': 'application/json' } });
  assert.equal(r.status, 400);
  r = await fetch(base + '/api/login', { method: 'POST', body: JSON.stringify({ email: 'x'.repeat(20_000) }), headers: { 'Content-Type': 'application/json' } });
  assert.equal(r.status, 413);
  r = await fetch(base + '/admin');
  assert.equal(r.status, 404);
  assert.deepEqual(await r.json(), { eroare: 'Pagina nu există.' });
});
