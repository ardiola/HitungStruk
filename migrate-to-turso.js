require("dotenv").config();

const path = require("path");
const { createClient } = require("@libsql/client");

const dbUrl = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

if (!dbUrl || !authToken) {
  throw new Error("TURSO_DATABASE_URL dan TURSO_AUTH_TOKEN wajib diisi");
}

function normalizeValue(value) {
  return typeof value === "bigint" ? Number(value) : value;
}

function normalizeRow(row) {
  const output = {};
  Object.entries(row).forEach(([key, value]) => {
    output[key] = normalizeValue(value);
  });
  return output;
}

async function ensureSchema(remoteDb) {
  await remoteDb.execute(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await remoteDb.execute(`CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  await remoteDb.execute(`CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    nama TEXT NOT NULL,
    no_rekening TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  await remoteDb.execute(`CREATE TABLE IF NOT EXISTS bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_amount REAL NOT NULL,
    discount_amount REAL DEFAULT 0,
    tax_amount REAL DEFAULT 0,
    grand_total REAL NOT NULL,
    split_count INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await remoteDb.execute(`CREATE TABLE IF NOT EXISTS bill_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bill_id INTEGER NOT NULL,
    item_name TEXT NOT NULL,
    item_amount REAL NOT NULL,
    person_id INTEGER,
    person_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bill_id) REFERENCES bills(id)
  )`);

  const peopleTableInfo = await remoteDb.execute("PRAGMA table_info(people)");
  const hasUserIdColumn = peopleTableInfo.rows.some(
    (row) => String(row.name || "").toLowerCase() === "user_id",
  );
  if (!hasUserIdColumn) {
    await remoteDb.execute("ALTER TABLE people ADD COLUMN user_id INTEGER");
  }
  await remoteDb.execute(
    "CREATE INDEX IF NOT EXISTS idx_people_user_id ON people(user_id)",
  );

  const usersTableInfo = await remoteDb.execute("PRAGMA table_info(users)");
  const hasRoleColumn = usersTableInfo.rows.some(
    (row) => String(row.name || "").toLowerCase() === "role",
  );
  if (!hasRoleColumn) {
    await remoteDb.execute(
      "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
    );
  }
  await remoteDb.execute(
    "UPDATE users SET role = 'user' WHERE role IS NULL OR TRIM(role) = ''",
  );
}

async function migrateTablePeople(localDb, remoteDb) {
  const localPeople = (await localDb.execute("SELECT * FROM people")).rows.map(
    normalizeRow,
  );
  let inserted = 0;

  for (const person of localPeople) {
    const exists = await remoteDb.execute({
      sql: "SELECT id FROM people WHERE id = ? LIMIT 1",
      args: [person.id],
    });
    if (exists.rows.length > 0) {
      continue;
    }

    await remoteDb.execute({
      sql: "INSERT INTO people (id, user_id, nama, no_rekening, created_at) VALUES (?, ?, ?, ?, ?)",
      args: [
        person.id,
        person.user_id !== undefined ? person.user_id : null,
        person.nama,
        person.no_rekening,
        person.created_at,
      ],
    });
    inserted += 1;
  }

  return { source: localPeople.length, inserted };
}

async function migrateTableBills(localDb, remoteDb) {
  const localBills = (await localDb.execute("SELECT * FROM bills")).rows.map(
    normalizeRow,
  );
  let inserted = 0;

  for (const bill of localBills) {
    const exists = await remoteDb.execute({
      sql: "SELECT id FROM bills WHERE id = ? LIMIT 1",
      args: [bill.id],
    });
    if (exists.rows.length > 0) {
      continue;
    }

    await remoteDb.execute({
      sql: `INSERT INTO bills (
        id, total_amount, discount_amount, tax_amount, grand_total, split_count, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        bill.id,
        bill.total_amount,
        bill.discount_amount,
        bill.tax_amount,
        bill.grand_total,
        bill.split_count,
        bill.created_at,
      ],
    });
    inserted += 1;
  }

  return { source: localBills.length, inserted };
}

async function migrateTableBillItems(localDb, remoteDb) {
  const localBillItems = (
    await localDb.execute("SELECT * FROM bill_items")
  ).rows.map(normalizeRow);
  let inserted = 0;

  for (const billItem of localBillItems) {
    const exists = await remoteDb.execute({
      sql: "SELECT id FROM bill_items WHERE id = ? LIMIT 1",
      args: [billItem.id],
    });
    if (exists.rows.length > 0) {
      continue;
    }

    await remoteDb.execute({
      sql: `INSERT INTO bill_items (
        id, bill_id, item_name, item_amount, person_id, person_name, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        billItem.id,
        billItem.bill_id,
        billItem.item_name,
        billItem.item_amount,
        billItem.person_id,
        billItem.person_name,
        billItem.created_at,
      ],
    });
    inserted += 1;
  }

  return { source: localBillItems.length, inserted };
}

async function main() {
  const localDb = createClient({
    url: `file:${path.resolve(__dirname, "database.db")}`,
  });

  const remoteDb = createClient({
    url: dbUrl,
    authToken,
  });

  await ensureSchema(remoteDb);

  const peopleResult = await migrateTablePeople(localDb, remoteDb);
  const billsResult = await migrateTableBills(localDb, remoteDb);
  const billItemsResult = await migrateTableBillItems(localDb, remoteDb);

  console.log("Migrasi Turso selesai.");
  console.log(
    `people: sumber ${peopleResult.source}, inserted ${peopleResult.inserted}`,
  );
  console.log(
    `bills: sumber ${billsResult.source}, inserted ${billsResult.inserted}`,
  );
  console.log(
    `bill_items: sumber ${billItemsResult.source}, inserted ${billItemsResult.inserted}`,
  );
}

main().catch((err) => {
  console.error("Gagal migrasi ke Turso:", err.message);
  process.exit(1);
});
