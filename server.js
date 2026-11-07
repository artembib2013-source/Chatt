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
CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, type TEXT DEFAULT 'group', is_private INTEGER DEFAULT 0, owner_id INTEGER, pinned_msg_id INTEGER, created_at INTEGER);
CREATE TABLE IF NOT EXISTS chat_members (chat_id INTEGER, user_id INTEGER, PRIMARY KEY (chat_id, user_id));
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER, user_id INTEGER, text TEXT, sticker TEXT, is_pinned INTEGER DEFAULT 0, created_at INTEGER);
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, seller_id INTEGER, title TEXT, price INTEGER, descr TEXT, image_url TEXT, status TEXT DEFAULT 'active', created_at INTEGER);
CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, contact TEXT, status TEXT DEFAULT 'pending', school TEXT, class_name TEXT, name TEXT, source TEXT, login TEXT, password TEXT, created_at INTEGER);
`);

// Миграции для старых баз
try { db.exec("ALTER TABLE chats ADD COLUMN type TEXT DEFAULT 'group'"); } catch(e){}
try { db.exec("ALTER TABLE chats ADD COLUMN owner_id INTEGER"); } catch(e){}
try { db.exec("ALTER TABLE chats ADD COLUMN pinned_msg_id INTEGER"); } catch(e){}
try { db.exec("ALTER TABLE messages ADD COLUMN is_pinned INTEGER DEFAULT 0"); } catch(e){}

if (!db.prepare('SELECT id FROM chats WHERE id=1').get()) {
  db.prepare('INSERT INTO chats(id, name, type, created_by, owner_id, created_at) VALUES (1, ?, ?, 0, 0, ?)').run('🏠 Главная группа', 'group', Date.now());
}

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

// --- ПРОФИЛИ ---
app.get('/api/profile/:username', auth, (rq, rs) => {
  const u = db.prepare('SELECT id, username, avatar, balance, bio, role FROM users WHERE username=?').get(rq.params.username);
  if (!u) return rs.status(404).json({ error: 'Не найден' });
  rs.json({ user: u });
});
app.post('/api/profile/update', auth, (rq, rs) => {
  const { username, bio, avatar } = rq.body;
  try {
    if (username && username !== rq.user.username) db.prepare('UPDATE users SET username=? WHERE id=?').run(username, rq.user.id);
    if (bio !== undefined) db.prepare('UPDATE users SET bio=? WHERE id=?').run(bio, rq.user.id);
    if (avatar !== undefined) db.prepare('UPDATE users SET avatar=? WHERE id=?').run(avatar, rq.user.id);
    rs.json({ ok: true });
  } catch (e) { rs.status(400).json({ error: 'Ник занят' }); }
});

// --- ЛИЧНЫЕ СООБЩЕНИЯ ---
app.post('/api/dm/start', auth, (rq, rs) => {
  const target = db.prepare('SELECT id, username, avatar FROM users WHERE username=?').get(rq.body.username);
  if (!target) return rs.status(404).json({ error: 'Нет юзера' });
  const exist = db.prepare(`SELECT c.id FROM chats c JOIN chat_members cm1 ON cm1.chat_id=c.id AND cm1.user_id=? JOIN chat_members cm2 ON cm2.chat_id=c.id AND cm2.user_id=? WHERE c.type = 'dm'`).get(rq.user.id, target.id);
  if (exist) return rs.json({ chatId: exist.id, name: target.username, avatar: target.avatar });
  
  const i = db.prepare('INSERT INTO chats(name, type, owner_id, created_at) VALUES (?, ?, ?, ?)').run('ЛС', 'dm', rq.user.id, Date.now());
  const cid = i.lastInsertRowid;
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(cid, rq.user.id);
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(cid, target.id);
  
  io.emit('new_chat_created');
  rs.json({ chatId: cid, name: target.username, avatar: target.avatar });
});

// --- ГРУППЫ И КАНАЛЫ ---
app.post('/api/chats', auth, (rq, rs) => {
  const { name, type, memberIds } = rq.body; // type: 'group' | 'channel'
  const i = db.prepare('INSERT INTO chats(name, type, owner_id, created_at) VALUES (?, ?, ?, ?)').run(name, type, rq.user.id, Date.now());
  const chatId = i.lastInsertRowid;
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(chatId, rq.user.id);
  if (memberIds) memberIds.forEach(id => db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(chatId, id));
  io.emit('new_chat_created'); rs.json({ ok: true, chatId });
});
app.post('/api/chats/:id/edit', auth, (rq, rs) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id=?').get(rq.params.id);
  if (!chat) return rs.status(404).json({error:'Нет чата'});
  if (chat.owner_id !== rq.user.id && rq.user.role !== 'admin') return rs.status(403).json({error:'Только владелец'});
  
  if(rq.body.newName) db.prepare('UPDATE chats SET name=? WHERE id=?').run(rq.body.newName, chat.id);
  rs.json({ ok: true });
});
app.post('/api/chats/:id/kick', auth, (rq, rs) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id=?').get(rq.params.id);
  if (!chat) return rs.status(404).json({error:'Нет чата'});
  if (chat.owner_id !== rq.user.id && rq.user.role !== 'admin') return rs.status(403).json({error:'Нет прав'});
  
  db.prepare('DELETE FROM chat_members WHERE chat_id=? AND user_id=?').run(chat.id, rq.body.userId);
  io.emit('new_chat_created');
  rs.json({ ok: true });
});
app.get('/api/chats/:id/members', auth, (rq, rs) => {
  const members = db.prepare('SELECT u.id, u.username FROM chat_members cm JOIN users u ON u.id = cm.user_id WHERE cm.chat_id = ?').all(rq.params.id);
  rs.json({ members });
});
app.post('/api/messages/:id/pin', auth, (rq, rs) => {
  const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(rq.params.id);
  if(!msg) return rs.status(404).json({error:'Нет сообщения'});
  const chat = db.prepare('SELECT * FROM chats WHERE id=?').get(msg.chat_id);
  if (chat.owner_id !== rq.user.id && rq.user.role !== 'admin') return rs.status(403).json({error:'Только владелец'});
  
  db.prepare('UPDATE chats SET pinned_msg_id=? WHERE id=?').run(msg.id, chat.id);
  io.to('chat_' + chat.id).emit('msg_pinned', { text: msg.text, username: db.prepare('SELECT username FROM users WHERE id=?').get(msg.user_id).username });
  rs.json({ ok: true });
});

// --- ЧАТЫ И СООБЩЕНИЯ ---
app.get('/api/chats', auth, (rq, rs) => {
  let chats = rq.user.role === 'admin' 
    ? db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as members_count FROM chats c ORDER BY c.id DESC`).all()
    : db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as members_count FROM chats c LEFT JOIN chat_members cm ON cm.chat_id = c.id AND cm.user_id = ? WHERE cm.user_id IS NOT NULL OR c.id = 1 ORDER BY c.id DESC`).all(rq.user.id);
  
  // Для ЛС подменяем название на ник собеседника
  chats = chats.map(c => {
    if (c.type === 'dm' && rq.user.role !== 'admin') {
      const peer = db.prepare(`SELECT u.username, u.avatar FROM users u JOIN chat_members cm ON cm.user_id=u.id WHERE cm.chat_id=? AND u.id != ?`).get(c.id, rq.user.id);
      if (peer) { c.name = peer.username; c.avatar = peer.avatar; }
    }
    return c;
  });
  rs.json({ chats });
});
app.get('/api/messages', auth, (rq, rs) => {
  const chat = db.prepare('SELECT * FROM chats WHERE id=?').get(rq.query.chat_id || 1);
  const m = db.prepare(`SELECT m.*, u.username, u.avatar FROM messages m JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.created_at ASC LIMIT 100`).all(rq.query.chat_id || 1);
  rs.json({ messages: m, chat });
});
app.get('/api/users', auth, (rq, rs) => rs.json({ users: db.prepare('SELECT id, username FROM users WHERE id != ? AND banned = 0').all(rq.user.id) }));

// --- МАГАЗИН ---
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
  const ci = db.prepare('INSERT INTO chats(name, type, owner_id, created_at) VALUES (?, ?, ?, ?)').run('Покупка', 'dm', p.seller_id, Date.now());
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(ci.lastInsertRowid, p.seller_id);
  db.prepare('INSERT INTO chat_members(chat_id, user_id) VALUES (?, ?)').run(ci.lastInsertRowid, rq.user.id);
  db.prepare('INSERT INTO messages(chat_id, user_id, text, created_at) VALUES (?, ?, ?, ?)').run(ci.lastInsertRowid, rq.user.id, `🛒 Покупка: ${p.title}`, Date.now());
  io.emit('new_chat_created'); rs.json({ ok: true, chatId: ci.lastInsertRowid });
});

// --- АДМИНКА ---
app.get('/api/admin/users', auth, adminOnly, (rq, rs) => rs.json({ users: db.prepare('SELECT id, username, role, banned, balance FROM users ORDER BY id').all() }));
app.post('/api/admin/user-details', auth, adminOnly, (rq, rs) => {
  const u = db.prepare('SELECT id, username, role, banned, balance, created_at FROM users WHERE id=?').get(rq.body.userId);
  const chats = db.prepare('SELECT c.name, c.type FROM chats c JOIN chat_members cm ON cm.chat_id=c.id WHERE cm.user_id=?').all(u.id);
  const bought = db.prepare('SELECT p.title, p.price FROM products p JOIN products_buyers pb ON pb.product_id = p.id WHERE pb.user_id=?').all(u.id); // Упрощенно
  const sold = db.prepare('SELECT title, price, status FROM products WHERE seller_id=?').all(u.id);
  rs.json({ user: u, chats, bought, sold });
});
app.post('/api/admin/delete-user', auth, adminOnly, (rq, rs) => {
  if(rq.body.userId == 1) return rs.status(400).json({error:'Нельзя удалить главного'});
  db.prepare('DELETE FROM users WHERE id=?').run(rq.body.userId);
  db.prepare('DELETE FROM chat_members WHERE user_id=?').run(rq.body.userId);
  db.prepare('DELETE FROM messages WHERE user_id=?').run(rq.body.userId);
  rs.json({ ok: true });
});

// --- СОКЕТЫ ---
io.on('connection', (s) => {
  const c = Object.fromEntries((s.handshake.headers.cookie || '').split(';').map(x => x.trim().split('=')));
  const u = getUser(c.token);
  if (!u || u.banned) { s.on('join_waiting', (contact) => s.join('waiting_' + contact)); return; }
  
  s.user = u;
  s.join('chat_1');
  const memberships = db.prepare('SELECT chat_id FROM chat_members WHERE user_id=?').all(s.user.id);
  memberships.forEach(m => s.join('chat_' + m.chat_id));
  
  s.on('join_chat', (chatId) => s.join('chat_' + chatId));
  s.on('message', ({ chatId, text, sticker }) => {
    const chat = db.prepare('SELECT type, owner_id FROM chats WHERE id=?').get(chatId);
    if (chat && chat.type === 'channel' && chat.owner_id !== s.user.id && s.user.role !== 'admin') return; // В канал пишет только владелец
    
    if (!text && !sticker) return;
    const i = db.prepare('INSERT INTO messages(chat_id, user_id, text, sticker, created_at) VALUES (?, ?, ?, ?, ?)').run(chatId, s.user.id, text||'', sticker||null, Date.now());
    io.to('chat_' + chatId).emit('message', { chat_id: chatId, id: i.lastInsertRowid, user_id: s.user.id, username: s.user.username, avatar: s.user.avatar, text: text||'', sticker: sticker||null, created_at: Date.now() });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('Сервер запущен на порту ' + PORT));
