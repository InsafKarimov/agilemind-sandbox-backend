const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const http = require('http');
const { hasProfanity, censorText } = require('./utils/badWords');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://agilemind-sandbox-frontend.netlify.app'
  ],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
      }
    : {
        user: 'postgres',
        password: 'Karimovinsaf2004',
        host: 'localhost',
        port: 5432,
        database: 'agilemind_sandbox'
      }
);

// ===== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ =====
const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      name VARCHAR(255) NOT NULL,
      methodology VARCHAR(50) DEFAULT 'Scrumban',
      data JSONB
    );

    CREATE TABLE IF NOT EXISTS achievements (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      key VARCHAR(100) NOT NULL,
      UNIQUE(user_id, key)
    );

    CREATE TABLE IF NOT EXISTS learning_progress (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      module_id INTEGER NOT NULL,
      completed BOOLEAN DEFAULT FALSE,
      UNIQUE(user_id, module_id)
    );

    CREATE TABLE IF NOT EXISTS team_messages (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ База данных готова');
};
initDB();

// ===== АУТЕНТИФИКАЦИЯ =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Введите имя и пароль' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, hashedPassword]
    );
    const token = jwt.sign({ userId: result.rows[0].id, username }, process.env.JWT_SECRET || 'secretkey');
    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ username, token });
  } catch (err) {
    res.status(400).json({ error: 'Пользователь уже существует' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (result.rows.length === 0) {
    return res.status(401).json({ error: 'Неверное имя или пароль' });
  }
  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Неверное имя или пароль' });
  }
  const token = jwt.sign({ userId: user.id, username }, process.env.JWT_SECRET || 'secretkey');
  res.cookie('token', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  res.json({ username, token });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    res.json({ username: decoded.username });
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
});

const auth = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
};

// ===== ПРОЕКТЫ =====
app.get('/api/projects', auth, async (req, res) => {
  const result = await pool.query('SELECT data FROM projects WHERE user_id = $1', [req.user.userId]);
  res.json(result.rows.map(r => r.data));
});

app.post('/api/projects', auth, async (req, res) => {
  const { projects } = req.body;
  await pool.query('DELETE FROM projects WHERE user_id = $1', [req.user.userId]);
  for (const project of projects) {
    await pool.query(
      'INSERT INTO projects (user_id, name, methodology, data) VALUES ($1, $2, $3, $4)',
      [req.user.userId, project.name, project.methodology, project]
    );
  }
  res.json({ success: true });
});

// ===== ДОСТИЖЕНИЯ =====
app.get('/api/achievements', auth, async (req, res) => {
  const result = await pool.query('SELECT key FROM achievements WHERE user_id = $1', [req.user.userId]);
  res.json(result.rows.map(r => r.key));
});

app.post('/api/achievements', auth, async (req, res) => {
  const { key } = req.body;
  try {
    await pool.query('INSERT INTO achievements (user_id, key) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.user.userId, key]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сохранения' });
  }
});

// ===== ОБУЧЕНИЕ =====
app.get('/api/learning', auth, async (req, res) => {
  const result = await pool.query('SELECT module_id, completed FROM learning_progress WHERE user_id = $1', [req.user.userId]);
  res.json(result.rows);
});

app.post('/api/learning', auth, async (req, res) => {
  const { modules } = req.body;
  for (const m of modules) {
    await pool.query(
      `INSERT INTO learning_progress (user_id, module_id, completed) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (user_id, module_id) 
       DO UPDATE SET completed = EXCLUDED.completed`,
      [req.user.userId, m.module_id, m.completed]
    );
  }
  res.json({ success: true });
});

// ===== WEBSOCKET ЧАТ =====
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: [
      'http://localhost:3000',
      'https://agilemind-sandbox-frontend.netlify.app'
    ],
    credentials: true
  }
});

const loadMessages = async () => {
  const result = await pool.query(
    'SELECT id, username, message, created_at as timestamp FROM team_messages ORDER BY created_at ASC LIMIT 100'
  );
  return result.rows;
};

const saveMessage = async (username, message) => {
  const result = await pool.query(
    'INSERT INTO team_messages (username, message) VALUES ($1, $2) RETURNING id, created_at',
    [username, message]
  );
  return {
    id: result.rows[0].id,
    username,
    message,
    timestamp: result.rows[0].created_at
  };
};

io.on('connection', async (socket) => {
  console.log('Пользователь подключился');
  
  const username = socket.handshake.auth.username;
  socket.username = username || 'Аноним';
  
  const history = await loadMessages();
  socket.emit('chat history', history);
  
  socket.on('chat message', async (msg) => {
  console.log('📨 Оригинал:', msg);
  console.log('🔞 Содержит мат?', hasProfanity(msg));
  const filteredMsg = censorText(msg);
  console.log('✅ После фильтрации:', filteredMsg);
  
  const saved = await saveMessage(socket.username, filteredMsg);
  io.emit('chat message', saved);
  });
  
  socket.on('delete message', async (messageId) => {
    const result = await pool.query('SELECT username FROM team_messages WHERE id = $1', [messageId]);
    if (result.rows.length === 0) return;
    
    if (result.rows[0].username !== socket.username) {
      socket.emit('error', 'Нельзя удалить чужое сообщение');
      return;
    }
    
    await pool.query('DELETE FROM team_messages WHERE id = $1', [messageId]);
    io.emit('message deleted', messageId);
  });
  
  socket.on('disconnect', () => {
    console.log('Пользователь отключился');
  });
});

const PORT = process.env.PORT || 5002;
server.listen(PORT, () => console.log(`🚀 Сервер на http://localhost:${PORT}`));