const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// База данных
const db = new Database('chat.db');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', created_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, user_id INTEGER, text TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, seller_id INTEGER, title TEXT, price INTEGER, descr TEXT, status TEXT DEFAULT 'active', created_at INTEGER);
`);

// Создаем админа при первом запуске
const DEV = 'dev';
const DEVP = 'dev12345';
if (!db.prepare('SELECT id FROM users WHERE username=?').get(DEV)) {
  db.prepare('INSERT INTO users(username, password, role, created_at) VALUES (?, ?, ?, ?)')
    .run(DEV, bcrypt.hashSync(DEVP, 10), 'dev', Date.now());
  console.log('Создан админ: dev / dev12345');
}

// Вспомогательные функции
const tok = () => crypto.randomBytes(32).toString('hex');

function getUser(t) {
  if (!t) return null;
  const s = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(t);
  if (!s) return null;
  return db.prepare('SELECT id, username, role FROM users WHERE id=?').get(s.user_id);
}

function auth(rq, rs, nx) {
  const u = getUser(rq.cookies.token);
  if (!u) return rs.status(401).json({ error: 'Не авторизован' });
  rq.user = u;
  nx();
}

// API: Регистрация и вход
app.post('/api/register', (rq, rs) => {
  const { username, password } = rq.body;
  if (!username || !password) return rs.status(400).json({ error: 'Заполни поля' });
  if (username.length < 3 || password.length < 5) return rs.status(400).json({ error: 'Логин ≥3, пароль ≥5' });
  if (username === 'dev') return rs.status(400).json({ error: 'Занято' });
  
  try {
    const h = bcrypt.hashSync(password, 10);
    const i = db.prepare('INSERT INTO users(username, password, created_at) VALUES (?, ?, ?)').run(username, h, Date.now());
    const t = tok();
    db.prepare('INSERT INTO sessions(token, user_id) VALUES (?, ?)').run(t, i.lastInsertRowid);
    rs.cookie('token', t, { httpOnly: true, sameSite: 'lax' });
    rs.json({ ok: true, user: { id: i.lastInsertRowid, username, role: 'user' } });
  } catch (e) {
    rs.status(400).json({ error: 'Логин занят' });
  }
});

app.post('/api/login', (rq, rs) => {
  const { username, password } = rq.body;
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!u || !bcrypt.compareSync(password, u.password)) return rs.status(400).json({ error: 'Неверный логин/пароль' });
  
  const t = tok();
  db.prepare('INSERT INTO sessions(token, user_id) VALUES (?, ?)').run(t, u.id);
  rs.cookie('token', t, { httpOnly: true, sameSite: 'lax' });
  rs.json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
});

// API: Сообщения и Товары
app.get('/api/messages', auth, (rq, rs) => {
  const m = db.prepare(`SELECT m.*, u.username FROM messages m JOIN users u ON u.id = m.user_id WHERE m.chat_id=1 ORDER BY m.created_at DESC LIMIT 100`).all().reverse();
  rs.json({ messages: m });
});

app.get('/api/products', auth, (rq, rs) => {
  const p = db.prepare(`SELECT p.*, u.username as seller FROM products p JOIN users u ON u.id = p.seller_id WHERE p.status='active' ORDER BY p.created_at DESC`).all();
  rs.json({ products: p });
});

app.post('/api/products', auth, (rq, rs) => {
  const { title, price, descr } = rq.body;
  if (!title || !price) return rs.status(400).json({ error: 'Заполни название и цену' });
  const i = db.prepare('INSERT INTO products(seller_id, title, price, descr, created_at) VALUES (?, ?, ?, ?, ?)').run(rq.user.id, title, +price, descr || '', Date.now());
  io.emit('new_product', { id: i.lastInsertRowid, title, price: +price, descr, seller: rq.user.username });
  rs.json({ ok: true });
});

app.post('/api/products/:id/buy', auth, (rq, rs) => {
  const p = db.prepare('SELECT * FROM products WHERE id=? AND status=?').get(+rq.params.id, 'active');
  if (!p) return rs.status(400).json({ error: 'Товар недоступен' });
  if (p.seller_id === rq.user.id) return rs.status(400).json({ error: 'Нельзя купить свой товар' });
  
  db.prepare('UPDATE products SET status=? WHERE id=?').run('sold', p.id);
  const text = `🛒 ${rq.user.username} купил «${p.title}» за ${p.price}₽`;
  const i = db.prepare('INSERT INTO messages(chat_id, user_id, text, created_at) VALUES (1, ?, ?, ?)').run(rq.user.id, text, Date.now());
  
  io.emit('message', { id: i.lastInsertRowid, user_id: rq.user.id, username: 'Система', text, created_at: Date.now() });
  rs.json({ ok: true });
});

// Сокеты (WebSocket для чата)
io.use((s, nx) => {
  const c = Object.fromEntries((s.handshake.headers.cookie || '').split(';').map(x => x.trim().split('=')));
  const u = getUser(c.token);
  if (!u) return nx(new Error('unauth'));
  s.user = u;
  nx();
});

io.on('connection', (s) => {
  s.join('main');
  s.on('message', ({ text }) => {
    if (!text || !s.user) return;
    const i = db.prepare('INSERT INTO messages(chat_id, user_id, text, created_at) VALUES (1, ?, ?, ?)').run(s.user.id, text, Date.now());
    io.to('main').emit('message', { id: i.lastInsertRowid, user_id: s.user.id, username: s.user.username, text, created_at: Date.now() });
  });
});

// Запуск
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('Сервер запущен на порту ' + PORT));
