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
