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

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database('chat.db');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', banned INTEGER DEFAULT 0, avatar TEXT, balance INTEGER DEFAULT 100, bio TEXT DEFAULT '', created_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER);
CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, is_private INTEGER DEFAULT 0, created_by INTEGER, created_at INTEGER);
CREATE TABLE IF NOT EXISTS chat_members (chat_id INTEGER, user_id INTEGER, PRIMARY KEY (chat_id, user_id));
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, user_id INTEGER, text TEXT, sticker TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, seller_id INTEGER, title TEXT, price INTEGER, descr TEXT, image_url TEXT, status TEXT DEFAULT 'active', created_at INTEGER);
CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, contact TEXT, status TEXT DEFAULT 'pending', school TEXT, class_name TEXT, name TEXT, source TEXT, login TEXT, password TEXT, created_at INTEGER);
`);

// Добавляем колонки в старую таблицу requests, если ее не было
try { db.exec("ALTER TABLE requests ADD COLUMN school TEXT"); } catch(e){}
try { db.exec("ALTER TABLE requests ADD COLUMN class_name TEXT"); } catch(e){}
try { db.exec("ALTER TABLE requests ADD COLUMN name TEXT"); } catch(e){}
try { db.exec("ALTER TABLE requests ADD COLUMN source TEXT"); } catch(e){}

// Главная группа
if (!db.prepare('SELECT id FROM chats WHERE id=1').get()) {
  db.prepare('INSERT INTO chats(id, name, created_by, created_at) VALUES (1, ?, 0, ?)').run('🏠 Главная группа', Date.now());
}

// Админ tutu / pipi
if (!db.prepare('SELECT id FROM users WHERE username=?').get('tutu')) {
  db.prepare('INSERT INTO users(username, password, role, banned, balance, created_at) VALUES (?, ?, ?, 0, ?, ?)')
    .run('tutu', bcrypt.hashSync('pipi', 10), 'admin', 1000000, Date.now());
}

const tok = () => crypto.randomBytes(32).toString('hex');
function getUser(t) {
  if (!t) return null;
  const s = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(t);
  if (!s) return null;
  return db.prepare('SELECT id, username, role, banned, avatar, balance, bio FROM users WHERE id=?').get(s.user_id);
}
function auth(rq, rs, nx) {
  const u = getUser(rq.cookies.token);
  if (!u) return rs.status(401).json({ error: 'Не авторизован' });
  if (u.banned) return rs.status(403).json({ error: 'Забанен' });
  rq.user = u; nx();
}
function adminOnly(rq, rs, nx) {
  if (rq.user.role !== 'admin') return rs.status(403).json({ error: 'Только админ' });
  nx();
}

// --- ЗАЯВКИ ---
app.post('/api/request', (rq, rs) => {
  const { contact } = rq.body;
  if (!contact) return rs.status(400).json({ error: 'Введи номер' });
  const i = db.prepare('INSERT INTO requests(contact, created_at) VALUES (?, ?)').run(contact, Date.now());
  io.emit('new_request');
  rs.json({ ok: true, requestId: i.lastInsertRowid });
});

app.post('/api/request/update', (rq, rs) => {
  const { id, school, class_name, name, source } = rq.body;
  db.prepare('UPDATE requests SET school=?, class_name=?, name=?, source=? WHERE id=?').run(school, class_name, name, source, id);
  rs.json({ ok: true });
});

// --- АВТОРИЗАЦИЯ ---
app.post('/api/login', (rq, rs) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(rq.body.username);
  if (!u || !bcrypt.compareSync(rq.body.password, u.password)) return rs.status(400).json({ error: 'Неверный логин/пароль' });
  if (u.banned) return rs.status(403).json({ error: 'Забанен' });
  const t = tok();
  db.prepare('INSERT INTO sessions(token, user_id) VALUES (?, ?)').run(t, u.id);
  rs.cookie('token', t, { httpOnly: true, sameSite: 'lax' });
  rs.json({ ok: true, user: { id: u.id, username: u.username, role: u.role, avatar: u.avatar, balance: u.balance } });
});
app.post('/api/logout', (rq, rs) => {
  const t = rq.cookies.token; if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  rs.clearCookie('token'); rs.json({ ok: true });
});

// --- АДМИН: ВЫДАЧА АККАУНТА ---
app.post('/api/admin/create-user', auth, adminOnly, (rq, rs) => {
  const { username, password, requestId } = rq.body;
  try {
    const h = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users(username, password, role, created_at) VALUES (?, ?, ?, ?)').run(username, h, 'user', Date.now());
    
    if (requestId) {
      db.prepare('UPDATE requests SET status=?, login=?, password=? WHERE id=?').run('done', username, password, requestId);
      const req = db.prepare('SELECT contact FROM requests WHERE id=?').get(requestId);
      // Отправляем всем в комнату ожидания
      if(req) io.to('waiting_' + req.contact).emit('request_approved', { login: username, password });
    }
    rs.json({ ok: true });
  } catch (e) { rs.status(400).json({ error: 'Логин занят' }); }
});

// --- ПРОФИЛИ, ЧАТЫ, МАГАЗИН ---
app.get('/api/profile/:username', auth, (rq, rs) => {
  const u = db.prepare('SELECT id, username, avatar, balance, bio, role FROM users WHERE username=?').get(rq.params.username);
  if (!u) return rs.status(404).json({ error: 'Не найден' });
  rs.json({ user: u });
});
app.post('/api/profile/update', auth, (rq, rs) => {
  const { username, bio, avatar } = rq.body;
  try {
    if (username && username !== rq.user.username && rq.user.role === 'admin') db.prepare('UPDATE users SET username=? WHERE id=?').run(username, rq.user.id);
    if (bio !== undefined) db.prepare('UPDATE users SET bio=? WHERE id=?').run(bio, rq.user.id);
    if (avatar !== undefined) db.prepare('UPDATE users SET avatar=? WHERE id=?').run(avatar, rq.user.id);
    rs.json({ ok: true });
  } catch (e) { rs.status(400).json({ error: 'Ник занят' }); }
});
app.post('/api/dm/start', auth, (rq, rs) => {
  const target = db.prepare('SELECT id FROM users WHERE username=?').get(rq.body.username);
  if (!target) return rs.status(404).json({ error: 'Нет такого юзера' });
  const exist = db.prepare(`SELECT c.id FROM chats c JOIN chat_members cm1 ON cm1.chat_id=c.id AND cm1.user_id=? JOIN chat_members cm2 ON cm2.chat_id=c.id AND cm2.user_id=? WHERE c.is_private = 1`).get(rq.user.id, target.id);
  if (exist) return rs.json({ chatId: exist.id });
  const i = db.prepare('INSERT INTO chats(name, is_private, created_by, created_at) VALUES (?, 1, ?, ?)').run('Личный чат', rq.user.id, Date.now());
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(i.lastInsertRowid, rq.user.id);
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(i.lastInsertRowid, target.id);
  io.emit('new_chat_created'); rs.json({ chatId: i.lastInsertRowid });
});
app.get('/api/chats', auth, (rq, rs) => {
  let chats = rq.user.role === 'admin' 
    ? db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as members_count FROM chats c ORDER BY c.id DESC`).all()
    : db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as members_count FROM chats c LEFT JOIN chat_members cm ON cm.chat_id = c.id AND cm.user_id = ? WHERE cm.user_id IS NOT NULL OR c.id = 1 ORDER BY c.id DESC`).all(rq.user.id);
  rs.json({ chats });
});
app.post('/api/chats', auth, (rq, rs) => {
  const { name, memberIds } = rq.body;
  const i = db.prepare('INSERT INTO chats(name, created_by, created_at) VALUES (?, ?, ?)').run(name, rq.user.id, Date.now());
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(i.lastInsertRowid, rq.user.id);
  if (memberIds) memberIds.forEach(id => db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(i.lastInsertRowid, id));
  io.emit('new_chat_created'); rs.json({ ok: true, chatId: i.lastInsertRowid });
});
app.get('/api/users', auth, (rq, rs) => rs.json({ users: db.prepare('SELECT id, username FROM users WHERE id != ? AND banned = 0').all(rq.user.id) }));
app.get('/api/messages', auth, (rq, rs) => rs.json({ messages: db.prepare(`SELECT m.*, u.username, u.avatar FROM messages m JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.created_at DESC LIMIT 100`).all(rq.query.chat_id || 1).reverse() }));
app.get('/api/products', auth, (rq, rs) => rs.json({ products: db.prepare(`SELECT p.*, u.username as seller FROM products p JOIN users u ON u.id = p.seller_id WHERE p.status='active' ORDER BY p.created_at DESC`).all() }));
app.post('/api/products', auth, (rq, rs) => {
  db.prepare('INSERT INTO products(seller_id, title, price, descr, image_url, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(rq.user.id, rq.body.title, +rq.body.price, rq.body.descr || '', rq.body.image_url || '', Date.now());
  io.emit('new_product'); rs.json({ ok: true });
});
app.post('/api/products/:id/buy', auth, (rq, rs) => {
  const p = db.prepare('SELECT * FROM products WHERE id=? AND status=?').get(+rq.params.id, 'active');
  if (!p || p.seller_id === rq.user.id) return rs.status(400).json({ error: 'Ошибка' });
  db.prepare('UPDATE products SET status=? WHERE id=?').run('sold', p.id);
  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(p.price, rq.user.id);
  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(p.price, p.seller_id);
  const ci = db.prepare('INSERT INTO chats(name, is_private, created_by, created_at) VALUES (?, 1, ?, ?)').run('Покупка', p.seller_id, Date.now());
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(ci.lastInsertRowid, p.seller_id);
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(ci.lastInsertRowid, rq.user.id);
  db.prepare('INSERT INTO messages(chat_id, user_id, text, created_at) VALUES (?, ?, ?, ?)').run(ci.lastInsertRowid, rq.user.id, `🛒 Куплен товар: ${p.title}`, Date.now());
  io.emit('new_chat_created'); rs.json({ ok: true, chatId: ci.lastInsertRowid });
});
app.get('/api/admin/users', auth, adminOnly, (rq, rs) => rs.json({ users: db.prepare('SELECT id, username, role, banned FROM users ORDER BY id').all() }));
app.get('/api/admin/requests', auth, adminOnly, (rq, rs) => rs.json({ requests: db.prepare('SELECT * FROM requests ORDER BY id DESC').all() }));

// --- СОКЕТЫ (ИСПРАВЛЕНО) ---
io.on('connection', (s) => {
  // Проверяем, авторизован ли пользователь
  const c = Object.fromEntries((s.handshake.headers.cookie || '').split(';').map(x => x.trim().split('=')));
  const u = getUser(c.token);
  
  // Если не авторизован — он может только слушать (нужно для заявок)
  if (!u || u.banned) {
    s.on('join_waiting', (contact) => s.join('waiting_' + contact));
    return;
  }
  
  // Если авторизован — полный доступ
  s.user = u;
  s.join('chat_1');
  const memberships = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(s.user.id);
  memberships.forEach(m => s.join('chat_' + m.chat_id));
  
  s.on('join_chat', (chatId) => s.join('chat_' + chatId));
  s.on('message', ({ chatId, text, sticker }) => {
    if (!text && !sticker) return;
    const i = db.prepare('INSERT INTO messages(chat_id, user_id, text, sticker, created_at) VALUES (?, ?, ?, ?, ?)').run(chatId, s.user.id, text||'', sticker||null, Date.now());
    io.to('chat_' + chatId).emit('message', { chat_id: chatId, id: i.lastInsertRowid, user_id: s.user.id, username: s.user.username, avatar: s.user.avatar, text: text||'', sticker: sticker||null, created_at: Date.now() });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('Сервер запущен на порту ' + PORT));
