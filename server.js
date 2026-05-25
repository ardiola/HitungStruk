require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const util = require('util');
const path = require('path');
const scryptAsync = util.promisify(crypto.scrypt);

const app = express();
const port = 3000;
const dbUrl = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

if (!dbUrl || !authToken) {
  throw new Error('TURSO_DATABASE_URL dan TURSO_AUTH_TOKEN wajib diisi');
}

const db = createClient({
  url: dbUrl,
  authToken,
});

function normalizeValue(value) {
  return typeof value === 'bigint' ? Number(value) : value;
}

function normalizeRow(row) {
  const normalized = {};
  Object.entries(row).forEach(([key, value]) => {
    normalized[key] = normalizeValue(value);
  });
  return normalized;
}

function normalizeRows(rows) {
  return rows.map((row) => normalizeRow(row));
}

async function initDatabase() {
  await db.execute(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await db.execute(`CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  await db.execute(`CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    nama TEXT NOT NULL,
    no_rekening TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  await db.execute(`CREATE TABLE IF NOT EXISTS bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_amount REAL NOT NULL,
    discount_amount REAL DEFAULT 0,
    tax_amount REAL DEFAULT 0,
    grand_total REAL NOT NULL,
    split_count INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await db.execute(`CREATE TABLE IF NOT EXISTS bill_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bill_id INTEGER NOT NULL,
    item_name TEXT NOT NULL,
    item_amount REAL NOT NULL,
    person_id INTEGER,
    person_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bill_id) REFERENCES bills(id)
  )`);

  const peopleTableInfo = await db.execute('PRAGMA table_info(people)');
  const hasUserIdColumn = peopleTableInfo.rows.some(
    (row) => String(row.name || '').toLowerCase() === 'user_id',
  );
  if (!hasUserIdColumn) {
    await db.execute('ALTER TABLE people ADD COLUMN user_id INTEGER');
  }
  await db.execute(
    'CREATE INDEX IF NOT EXISTS idx_people_user_id ON people(user_id)',
  );

  const usersTableInfo = await db.execute('PRAGMA table_info(users)');
  const hasRoleColumn = usersTableInfo.rows.some(
    (row) => String(row.name || '').toLowerCase() === 'role',
  );
  if (!hasRoleColumn) {
    await db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
  }
  await db.execute("UPDATE users SET role = 'user' WHERE role IS NULL OR TRIM(role) = ''");
}

let databaseInitPromise = null;

function ensureDatabaseInitialized() {
  if (!databaseInitPromise) {
    databaseInitPromise = initDatabase();
  }
  return databaseInitPromise;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, hashedPassword) {
  const [salt, storedHash] = String(hashedPassword || '').split(':');
  if (!salt || !storedHash) {
    return false;
  }
  const derivedKey = await scryptAsync(password, salt, 64);
  return crypto.timingSafeEqual(
    Buffer.from(storedHash, 'hex'),
    Buffer.from(derivedKey.toString('hex'), 'hex'),
  );
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const result = await db.execute({
      sql: `SELECT u.id, u.username, u.role, t.token
            FROM auth_tokens t
            JOIN users u ON u.id = t.user_id
            WHERE t.token = ? AND t.expires_at > ? LIMIT 1`,
      args: [token, Date.now()],
    });
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    req.user = normalizeRow(result.rows[0]);
    req.token = token;
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

function authorizeAdmin(req, res, next) {
  if (String(req.user?.role || '').toLowerCase() !== 'admin') {
    return res.status(403).json({ error: 'Akses admin diperlukan' });
  }
  next();
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/auth/register', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) {
    return res.status(400).json({ error: 'username dan password wajib diisi' });
  }

  try {
    const duplicateCheck = await db.execute({
      sql: 'SELECT id FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1',
      args: [username],
    });
    if (duplicateCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Username sudah digunakan' });
    }

    const passwordHash = await hashPassword(password);
    const insertResult = await db.execute({
      sql: "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user') RETURNING id, username, role",
      args: [username, passwordHash],
    });
    const user = normalizeRow(insertResult.rows[0] || {});

    res.status(201).json({
      registered: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) {
    return res.status(400).json({ error: 'username dan password wajib diisi' });
  }

  try {
    const userResult = await db.execute({
      sql: 'SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1',
      args: [username],
    });

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const user = normalizeRow(userResult.rows[0]);
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const token = generateToken();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await db.execute({
      sql: 'INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
      args: [user.id, token, expiresAt],
    });

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

app.get('/api/users', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const result = await db.execute({
      sql: 'SELECT id, username, role, created_at FROM users ORDER BY id ASC',
    });
    res.json(normalizeRows(result.rows));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', authenticate, authorizeAdmin, async (req, res) => {
  const targetUserId = Number(req.params.id);
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).json({ error: 'ID user tidak valid' });
  }
  if (targetUserId === Number(req.user.id)) {
    return res.status(400).json({ error: 'Admin tidak bisa menghapus akun sendiri' });
  }

  try {
    const userResult = await db.execute({
      sql: 'SELECT id FROM users WHERE id = ? LIMIT 1',
      args: [targetUserId],
    });
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User tidak ditemukan' });
    }

    await db.execute({
      sql: 'DELETE FROM auth_tokens WHERE user_id = ?',
      args: [targetUserId],
    });
    await db.execute({
      sql: 'DELETE FROM people WHERE user_id = ?',
      args: [targetUserId],
    });
    await db.execute({
      sql: 'DELETE FROM users WHERE id = ?',
      args: [targetUserId],
    });

    res.json({ deleted: true, user_id: targetUserId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    await db.execute({
      sql: 'DELETE FROM auth_tokens WHERE token = ?',
      args: [req.token],
    });
    res.json({ loggedOut: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/people', authenticate, async (req, res) => {
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM people WHERE user_id = ? ORDER BY nama',
      args: [req.user.id],
    });
    res.json(normalizeRows(result.rows));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/people', authenticate, async (req, res) => {
  const nama = String(req.body?.nama || '').trim();
  const noRekening = String(req.body?.no_rekening || '').trim();

  if (!nama || !noRekening) {
    return res.status(400).json({ error: 'nama dan no_rekening wajib diisi' });
  }

  try {
    const duplicateCheck = await db.execute({
      sql: `SELECT id FROM people
            WHERE user_id = ? AND LOWER(TRIM(nama)) = LOWER(TRIM(?))
            LIMIT 1`,
      args: [req.user.id, nama],
    });

    if (duplicateCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Nama teman sudah ada' });
    }

    const insertResult = await db.execute({
      sql: 'INSERT INTO people (user_id, nama, no_rekening) VALUES (?, ?, ?) RETURNING id',
      args: [req.user.id, nama, noRekening],
    });
    const inserted = normalizeRow(insertResult.rows[0] || {});
    res.json({ id: inserted.id, nama, no_rekening: noRekening });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/people/:id', authenticate, async (req, res) => {
  try {
    const deleteResult = await db.execute({
      sql: 'DELETE FROM people WHERE id = ? AND user_id = ?',
      args: [req.params.id, req.user.id],
    });
    const affectedRows = normalizeValue(deleteResult.rowsAffected || 0);
    if (affectedRows === 0) {
      return res.status(404).json({ error: 'Data teman tidak ditemukan' });
    }
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/bills', authenticate, async (req, res) => {
  const { total_amount, discount_amount, tax_amount, grand_total, split_count, personBills } = req.body;

  try {
    const billInsertResult = await db.execute({
      sql: 'INSERT INTO bills (total_amount, discount_amount, tax_amount, grand_total, split_count) VALUES (?, ?, ?, ?, ?) RETURNING id',
      args: [total_amount, discount_amount, tax_amount, grand_total, split_count],
    });
    const billId = normalizeValue(billInsertResult.rows[0]?.id);

    if (personBills && personBills.length > 0) {
      for (const personBill of personBills) {
        await db.execute({
          sql: 'INSERT INTO bill_items (bill_id, item_name, item_amount, person_id, person_name) VALUES (?, ?, ?, ?, ?)',
          args: [billId, personBill.name, personBill.amount, personBill.personId, personBill.personName],
        });
      }
    }

    res.json({ id: billId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/bills', authenticate, async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM bills ORDER BY created_at DESC LIMIT 50');
    res.json(normalizeRows(result.rows));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/bills/:id', authenticate, async (req, res) => {
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM bills WHERE id = ?',
      args: [req.params.id],
    });
    const bill = result.rows[0] ? normalizeRow(result.rows[0]) : null;
    res.json(bill);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use((err, req, res, next) => {
  if (req.path && req.path.startsWith('/api/')) {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      return res.status(400).json({ error: 'Format JSON tidak valid' });
    }
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }

  return next(err);
});

async function startServer() {
  try {
    await ensureDatabaseInitialized();
    app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  } catch (err) {
    console.error('Gagal inisialisasi database Turso:', err.message);
    process.exit(1);
  }
}

if (!process.env.VERCEL) {
  startServer();
}

module.exports = {
  app,
  ensureDatabaseInitialized,
};