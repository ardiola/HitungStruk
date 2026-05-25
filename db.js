require('dotenv').config();

const { createClient } = require('@libsql/client');

const dbUrl = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

if (!dbUrl || !authToken) {
  throw new Error('TURSO_DATABASE_URL dan TURSO_AUTH_TOKEN wajib diisi');
}

const db = createClient({
  url: dbUrl,
  authToken,
});

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

initDatabase()
  .then(() => {
    console.log('Database Turso dan tabel berhasil dibuat');
  })
  .catch((err) => {
    console.error('Gagal membuat tabel di Turso:', err.message);
    process.exit(1);
  });