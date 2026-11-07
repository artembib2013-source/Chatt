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

const db = new Database('chat.db');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', banned INTEGER DEFAULT 0, created_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, created_by INTEGER, created_at INTEGER);
CREATE TABLE IF NOT EXISTS chat_members (chat_id INTEGER, user_id INTEGER, PRIMARY KEY (chat_id, user_id));
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, user_id INTEGER, text TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, seller_id INTEGER, title TEXT, price INTEGER, descr TEXT, image_url TEXT, status TEXT DEFAULT 'active', created_at INTEGER);
CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, contact TEXT, status TEXT DEFAULT 'pending', login TEXT, password TEXT, created_at INTEGER);
`);

// Главная группа
if (!db.prepare('SELECT id FROM chats WHERE id=1').get()) {
  db.prepare('INSERT INTO chats(id, name, created_by, created_at) VALUES (1, ?, 0, ?)').run('🏠 Главная группа', Date.now());
}

// Админ tutu / pipi
const ADMIN_LOGIN = 'tutu';
const ADMIN_PASS = 'pipi';
if (!db.prepare('SELECT id FROM users WHERE username=?').get(ADMIN_LOGIN)) {
  db.prepare('INSERT INTO users(username, password, role, banned, created_at) VALUES (?, ?, ?, 0, ?)')
    .run(ADMIN_LOGIN, bcrypt.hashSync(ADMIN_PASS, 10), 'admin', Date.now());
  console.log('Создан админ: tutu / pipi');
}

const tok = () => crypto.randomBytes(32).toString('hex');
function getUser(t) {
  if (!t) return null;
  const s = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(t);
  if (!s) return null;
  return db.prepare('SELECT id, username, role, banned FROM users WHERE id=?').get(s.user_id);
}
function auth(rq, rs, nx) {
  const u = getUser(rq.cookies.token);
  if (!u) return rs.status(401).json({ error: 'Не авторизован' });
  if (u.banned) return rs.status(403).json({ error: 'Забанен' });
  rq.user = u;
  nx();
}
function adminOnly(rq, rs, nx) {
  if (rq.user.role !== 'admin') return rs.status(403).json({ error: 'Только админ' });
  nx();
}

// --- ЗАЯВКИ НА РЕГИСТРАЦИЮ ---
app.post('/api/request', (rq, rs) => {
  const { contact } = rq.body;
  if (!contact) return rs.status(400).json({ error: 'Введи номер или имя' });
  db.prepare('INSERT INTO requests(contact, created_at) VALUES (?, ?)').run(contact, Date.now());
  io.emit('new_request'); // Уведомить админа
  rs.json({ ok: true });
});

app.post('/api/check-request', (rq, rs) => {
  const { contact } = rq.body;
  const req = db.prepare('SELECT * FROM requests WHERE contact=? ORDER BY id DESC LIMIT 1').get(contact);
  if (!req) return rs.status(404).json({ error: 'Заявка не найдена' });
  if (req.status === 'pending') return rs.json({ status: 'pending' });
  rs.json({ status: 'done', login: req.login, password: req.password });
});

// --- АВТОРИЗАЦИЯ ---
app.post('/api/login', (rq, rs) => {
  const { username, password } = rq.body;
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!u || !bcrypt.compareSync(password, u.password)) return rs.status(400).json({ error: 'Неверный логин/пароль' });
  if (u.banned) return rs.status(403).json({ error: 'Аккаунт забанен' });
  const t = tok();
  db.prepare('INSERT INTO sessions(token, user_id) VALUES (?, ?)').run(t, u.id);
  rs.cookie('token', t, { httpOnly: true, sameSite: 'lax' });
  rs.json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
});

app.post('/api/logout', (rq, rs) => {
  const t = rq.cookies.token;
  if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  rs.clearCookie('token');
  rs.json({ ok: true });
});

// --- АДМИН ---
app.post('/api/admin/create-user', auth, adminOnly, (rq, rs) => {
  const { username, password, requestId } = rq.body;
  if (!username || !password) return rs.status(400).json({ error: 'Заполни поля' });
  try {
    const h = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users(username, password, role, created_at) VALUES (?, ?, ?, ?)').run(username, h, 'user', Date.now());
    if (requestId) {
      db.prepare('UPDATE requests SET status=?, login=?, password=? WHERE id=?').run('done', username, password, requestId);
    }
    rs.json({ ok: true });
  } catch (e) { rs.status(400).json({ error: 'Логин занят' }); }
});

app.get('/api/admin/requests', auth, adminOnly, (rq, rs) => {
  const reqs = db.prepare('SELECT * FROM requests ORDER BY id DESC').all();
  rs.json({ requests: reqs });
});

app.get('/api/admin/users', auth, adminOnly, (rq, rs) => {
  const users = db.prepare('SELECT id, username, role, banned FROM users ORDER BY id').all();
  rs.json({ users });
});

app.post('/api/admin/ban', auth, adminOnly, (rq, rs) => {
  const { userId, banned } = rq.body;
  db.prepare('UPDATE users SET banned=? WHERE id=?').run(banned ? 1 : 0, userId);
  rs.json({ ok: true });
});

app.post('/api/admin/emergency-clear', auth, adminOnly, (rq, rs) => {
  db.prepare('DELETE FROM messages').run();
  db.prepare('DELETE FROM products').run();
  io.emit('emergency_clear');
  rs.json({ ok: true });
});

// --- ЧАТЫ ---
app.get('/api/chats', auth, (rq, rs) => {
  let chats;
  if (rq.user.role === 'admin') {
    chats = db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as members_count FROM chats c ORDER BY c.id ASC`).all();
  } else {
    chats = db.prepare(`
      SELECT c.*, (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as members_count
      FROM chats c LEFT JOIN chat_members cm ON cm.chat_id = c.id AND cm.user_id = ?
      WHERE cm.user_id IS NOT NULL OR c.id = 1 ORDER BY c.id ASC
    `).all(rq.user.id);
  }
  rs.json({ chats });
});

app.post('/api/chats', auth, (rq, rs) => {
  const { name, memberIds } = rq.body;
  if (!name) return rs.status(400).json({ error: 'Введи название' });
  const i = db.prepare('INSERT INTO chats(name, created_by, created_at) VALUES (?, ?, ?)').run(name, rq.user.id, Date.now());
  const chatId = i.lastInsertRowid;
  const addMember = db.prepare('INSERT OR IGNORE INTO chat_members(chat_id, user_id) VALUES (?, ?)');
  addMember.run(chatId, rq.user.id);
  if (memberIds && Array.isArray(memberIds)) memberIds.forEach(id => addMember.run(chatId, id));
  io.emit('new_chat_created'); 
  rs.json({ ok: true, chatId });
});

app.get('/api/users', auth, (rq, rs) => {
  const users = db.prepare('SELECT id, username FROM users WHERE id != ? AND banned = 0').all(rq.user.id);
  rs.json({ users });
});

app.get('/api/messages', auth, (rq, rs) => {
  const chatId = rq.query.chat_id || 1;
  if (chatId != 1 && rq.user.role !== 'admin') {
    const isMember = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chatId, rq.user.id);
    if (!isMember) return rs.status(403).json({ error: 'Нет доступа' });
  }
  const m = db.prepare(`SELECT m.*, u.username FROM messages m JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.created_at DESC LIMIT 100`).all(chatId).reverse();
  rs.json({ messages: m });
});

// --- МАГАЗИН ---
app.get('/api/products', auth, (rq, rs) => {
  const p = db.prepare(`SELECT p.*, u.username as seller FROM products p JOIN users u ON u.id = p.seller_id WHERE p.status='active' ORDER BY p.created_at DESC`).all();
  rs.json({ products: p });
});

app.post('/api/products', auth, (rq, rs) => {
  const { title, price, descr, image_url } = rq.body;
  if (!title || !price) return rs.status(400).json({ error: 'Заполни название и цену' });
  const i = db.prepare('INSERT INTO products(seller_id, title, price, descr, image_url, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(rq.user.id, title, +price, descr || '', image_url || '', Date.now());
  io.emit('new_product', { id: i.lastInsertRowid, title, price: +price, descr, image_url, seller: rq.user.username });
  rs.json({ ok: true });
});

app.post('/api/products/:id/buy', auth, (rq, rs) => {
  const p = db.prepare('SELECT * FROM products WHERE id=? AND status=?').get(+rq.params.id, 'active');
  if (!p) return rs.status(400).json({ error: 'Товар недоступен' });
  if (p.seller_id === rq.user.id) return rs.status(400).json({ error: 'Свой товар' });
  
  db.prepare('UPDATE products SET status=? WHERE id=?').run('sold', p.id);

  let personalChatId = null;
  const exist = db.prepare(`
    SELECT c.id FROM chats c 
    JOIN chat_members cm1 ON cm1.chat_id=c.id AND cm1.user_id=?
    JOIN chat_members cm2 ON cm2.chat_id=c.id AND cm2.user_id=?
    WHERE (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) = 2
  `).get(p.seller_id, rq.user.id);

  if (exist) {
    personalChatId = exist.id;
  } else {
    const chatName = `Покупка: ${rq.user.username} ↔ ${db.prepare('SELECT username FROM users WHERE id=?').get(p.seller_id).username}`;
    const ci = db.prepare('INSERT INTO chats(name, created_by, created_at) VALUES (?, ?, ?)').run(chatName, p.seller_id, Date.now());
    personalChatId = ci.lastInsertRowid;
    db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(personalChatId, p.seller_id);
    db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(personalChatId, rq.user.id);
  }

  const text = `🛒 ${rq.user.username} купил «${p.title}» за ${p.price}₽`;
  const mi = db.prepare('INSERT INTO messages(chat_id, user_id, text, created_at) VALUES (?, ?, ?, ?)').run(personalChatId, rq.user.id, text, Date.now());
  
  io.emit('new_chat_created'); 
  io.to('chat_' + personalChatId).emit('message', { chat_id: personalChatId, id: mi.lastInsertRowid, user_id: rq.user.id, username: 'Система', text, created_at: Date.now() });
  
  rs.json({ ok: true, chatId: personalChatId });
});

// --- СОКЕТЫ ---
io.use((s, nx) => {
  const c = Object.fromEntries((s.handshake.headers.cookie || '').split(';').map(x => x.trim().split('=')));
  const u = getUser(c.token);
  if (!u || u.banned) return nx(new Error('unauth'));
  s.user = u;
  nx();
});

io.on('connection', (s) => {
  s.join('chat_1');
  const memberships = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(s.user.id);
  memberships.forEach(m => s.join('chat_' + m.chat_id));

  s.on('join_chat', (chatId) => {
    if(chatId == 1 || s.user.role === 'admin') return s.join('chat_' + chatId);
    const m = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chatId, s.user.id);
    if(m) s.join('chat_' + chatId);
  });

  s.on('message', ({ chatId, text }) => {
    if (!text || !s.user) return;
    if (chatId != 1 && s.user.role !== 'admin') {
      const m = db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').get(chatId, s.user.id);
      if (!m) return;
    }
    const i = db.prepare('INSERT INTO messages(chat_id, user_id, text, created_at) VALUES (?, ?, ?, ?)').run(chatId, s.user.id, text, Date.now());
    io.to('chat_' + chatId).emit('message', { chat_id: chatId, id: i.lastInsertRowid, user_id: s.user.id, username: s.user.username, text, created_at: Date.now() });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('Сервер запущен на порту ' + PORT));
