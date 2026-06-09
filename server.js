require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const { createClient } = require("@libsql/client");
const crypto = require("crypto");
const util = require("util");
const path = require("path");
const scryptAsync = util.promisify(crypto.scrypt);

const app = express();
const port = 3000;
const dbUrl = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;
const MAX_JSON_BODY_SIZE = process.env.MAX_JSON_BODY_SIZE || "12mb";
const MAX_USERNAME_LENGTH = 32;
const MAX_PASSWORD_LENGTH = 128;
const MAX_PERSON_NAME_LENGTH = 80;
const MAX_REKENING_LENGTH = 30;
const MAX_SPLIT_COUNT = 100;
const MAX_PERSON_BILLS = 200;
const MAX_OCR_IMAGE_DATA_URL_LENGTH = 10 * 1024 * 1024;
const AUTH_COOKIE_NAME = "auth_token";
const LOGIN_LOCK_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_THRESHOLD = 8;
const LOGIN_LOCK_DURATION_MS = 15 * 60 * 1000;

const parsedAllowedOrigins = String(process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);
const allowedOrigins = new Set(parsedAllowedOrigins);
const failedLoginAttempts = new Map();

app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "https://cdn.jsdelivr.net",
          "blob:",
          "data:",
        ],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", "https://cdn.jsdelivr.net", "blob:", "data:"],
        workerSrc: ["'self'", "blob:", "https://cdn.jsdelivr.net"],
        fontSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.size === 0 || allowedOrigins.has(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Origin tidak diizinkan oleh CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(
  bodyParser.json({
    limit: MAX_JSON_BODY_SIZE,
    strict: true,
    type: "application/json",
  }),
);
app.use(cookieParser());
app.use(express.static(__dirname));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Terlalu banyak percobaan login/register. Coba lagi beberapa saat.",
  },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Terlalu banyak permintaan. Coba lagi beberapa saat." },
});

app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);
app.use("/api", rejectSuspiciousRequest);

if (!dbUrl || !authToken) {
  throw new Error("TURSO_DATABASE_URL dan TURSO_AUTH_TOKEN wajib diisi");
}

const db = createClient({
  url: dbUrl,
  authToken,
});

function normalizeValue(value) {
  return typeof value === "bigint" ? Number(value) : value;
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

function sanitizeTextInput(value) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function sanitizeUsername(value) {
  return sanitizeTextInput(value).toLowerCase();
}

function sanitizeRekening(value) {
  return String(value || "")
    .replace(/[^\d]/g, "")
    .trim();
}

function isValidUsername(username) {
  return /^[a-z0-9._-]{3,32}$/.test(username);
}

function isValidPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= MAX_PASSWORD_LENGTH
  );
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function isValidPositiveInt(value, maxValue = Number.MAX_SAFE_INTEGER) {
  return Number.isInteger(value) && value > 0 && value <= maxValue;
}

function containsSqlInjectionPattern(value) {
  if (typeof value !== "string") {
    return false;
  }
  return /(\bunion\s+select\b|\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\binformation_schema\b|\bsleep\s*\(|\bbenchmark\s*\(|--|\/\*|\*\/)/i.test(
    value,
  );
}

function hasSuspiciousPayload(input) {
  if (typeof input === "string") {
    return containsSqlInjectionPattern(input);
  }
  if (Array.isArray(input)) {
    return input.some((item) => hasSuspiciousPayload(item));
  }
  if (input && typeof input === "object") {
    return Object.entries(input).some(([key, value]) => {
      if (/password/i.test(String(key))) {
        return false;
      }
      return hasSuspiciousPayload(value);
    });
  }
  return false;
}

function rejectSuspiciousRequest(req, res, next) {
  if (
    hasSuspiciousPayload(req.query) ||
    hasSuspiciousPayload(req.params) ||
    hasSuspiciousPayload(req.body)
  ) {
    return res
      .status(400)
      .json({ error: "Permintaan terdeteksi mencurigakan" });
  }
  return next();
}

function sendServerError(res, err, context) {
  if (context) {
    console.error(`[${context}]`, err);
  } else {
    console.error(err);
  }
  return res.status(500).json({ error: "Terjadi kesalahan pada server" });
}

async function runOcrFromBuffer(imageBuffer) {
  console.log("runOcrFromBuffer: Starting OCR...");
  try {
    const { runOcr } = require("./ocr.js");
    console.log("runOcrFromBuffer: Calling runOcr...");
    const text = await runOcr(imageBuffer);
    console.log(
      "runOcrFromBuffer: OCR completed, text length:",
      text?.length || 0,
    );
    return { success: true, text };
  } catch (err) {
    console.error("runOcrFromBuffer: OCR failed:", err.message);
    return { success: false, error: err.message };
  }
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "")
    .split(",")[0]
    .trim();
  if (forwarded) {
    return forwarded;
  }
  return req.ip || req.socket?.remoteAddress || "unknown";
}

function getLoginAttemptKey(req, username) {
  return `${sanitizeUsername(username)}::${getClientIp(req)}`;
}

function cleanupExpiredLoginAttempt(key, now) {
  const record = failedLoginAttempts.get(key);
  if (!record) {
    return;
  }
  if (record.lockUntil && record.lockUntil > now) {
    return;
  }
  if (now - record.lastAttemptAt > LOGIN_LOCK_WINDOW_MS) {
    failedLoginAttempts.delete(key);
  }
}

function getLoginBackoffMs(failedCount) {
  if (failedCount <= 1) {
    return 0;
  }
  return Math.min(500 * (failedCount - 1), 4000);
}

async function applyLoginFailure(req, username) {
  const key = getLoginAttemptKey(req, username);
  const now = Date.now();
  const current = failedLoginAttempts.get(key) || {
    failedCount: 0,
    lastAttemptAt: now,
    lockUntil: 0,
  };
  current.failedCount += 1;
  current.lastAttemptAt = now;
  if (current.failedCount >= LOGIN_LOCK_THRESHOLD) {
    current.lockUntil = now + LOGIN_LOCK_DURATION_MS;
  }
  failedLoginAttempts.set(key, current);
  const backoffMs = getLoginBackoffMs(current.failedCount);
  if (backoffMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, backoffMs));
  }
  return current;
}

function clearLoginFailure(req, username) {
  failedLoginAttempts.delete(getLoginAttemptKey(req, username));
}

function getCookieOptions(req) {
  const origin = String(req.headers.origin || "").trim();
  const host = req.get("host");
  const protocol = req.protocol || "http";
  const currentOrigin = host ? `${protocol}://${host}` : "";
  const isCrossOrigin = !!origin && !!currentOrigin && origin !== currentOrigin;
  const isProduction = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: isProduction || isCrossOrigin,
    sameSite: isCrossOrigin ? "none" : "lax",
    maxAge: 24 * 60 * 60 * 1000,
    path: "/",
  };
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

  const peopleTableInfo = await db.execute("PRAGMA table_info(people)");
  const hasUserIdColumn = peopleTableInfo.rows.some(
    (row) => String(row.name || "").toLowerCase() === "user_id",
  );
  if (!hasUserIdColumn) {
    await db.execute("ALTER TABLE people ADD COLUMN user_id INTEGER");
  }
  await db.execute(
    "CREATE INDEX IF NOT EXISTS idx_people_user_id ON people(user_id)",
  );

  const usersTableInfo = await db.execute("PRAGMA table_info(users)");
  const hasRoleColumn = usersTableInfo.rows.some(
    (row) => String(row.name || "").toLowerCase() === "role",
  );
  if (!hasRoleColumn) {
    await db.execute(
      "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
    );
  }
  await db.execute(
    "UPDATE users SET role = 'user' WHERE role IS NULL OR TRIM(role) = ''",
  );
}

let databaseInitPromise = null;

function ensureDatabaseInitialized() {
  if (!databaseInitPromise) {
    databaseInitPromise = initDatabase();
  }
  return databaseInitPromise;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(password, salt, 64);
  return `${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, hashedPassword) {
  const [salt, storedHash] = String(hashedPassword || "").split(":");
  if (!salt || !storedHash) {
    return false;
  }
  const derivedKey = await scryptAsync(password, salt, 64);
  return crypto.timingSafeEqual(
    Buffer.from(storedHash, "hex"),
    Buffer.from(derivedKey.toString("hex"), "hex"),
  );
}

function generateToken() {
  return crypto.randomBytes(48).toString("hex");
}

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const [scheme, bearerToken] = authHeader.split(" ");
  const cookieToken = req.cookies?.[AUTH_COOKIE_NAME];
  const token = scheme === "Bearer" && bearerToken ? bearerToken : cookieToken;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
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
      return res.status(401).json({ error: "Unauthorized" });
    }

    req.user = normalizeRow(result.rows[0]);
    req.token = token;
    next();
  } catch (err) {
    sendServerError(res, err, "authenticate");
  }
}

function authorizeAdmin(req, res, next) {
  if (String(req.user?.role || "").toLowerCase() !== "admin") {
    return res.status(403).json({ error: "Akses admin diperlukan" });
  }
  next();
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/api/auth/register", async (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const password = String(req.body?.password || "");
  if (!username || !password) {
    return res.status(400).json({ error: "username dan password wajib diisi" });
  }
  if (!isValidUsername(username)) {
    return res.status(400).json({
      error: `username harus 3-${MAX_USERNAME_LENGTH} karakter (huruf kecil, angka, titik, underscore, atau dash)`,
    });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: "password harus 8-128 karakter" });
  }

  try {
    const duplicateCheck = await db.execute({
      sql: "SELECT id FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
      args: [username],
    });
    if (duplicateCheck.rows.length > 0) {
      return res.status(409).json({ error: "Username sudah digunakan" });
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
    sendServerError(res, err, "auth-register");
  }
});

app.post("/api/auth/login", async (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const password = String(req.body?.password || "");
  if (!username || !password) {
    return res.status(400).json({ error: "username dan password wajib diisi" });
  }
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: "format username tidak valid" });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: "format password tidak valid" });
  }

  const loginAttemptKey = getLoginAttemptKey(req, username);
  const now = Date.now();
  cleanupExpiredLoginAttempt(loginAttemptKey, now);
  const loginAttemptState = failedLoginAttempts.get(loginAttemptKey);
  if (loginAttemptState && loginAttemptState.lockUntil > now) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((loginAttemptState.lockUntil - now) / 1000),
    );
    res.setHeader("Retry-After", String(retryAfterSeconds));
    return res.status(429).json({
      error: `Akun sementara dikunci. Coba lagi dalam ${retryAfterSeconds} detik.`,
    });
  }

  try {
    const userResult = await db.execute({
      sql: "SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
      args: [username],
    });

    if (userResult.rows.length === 0) {
      await applyLoginFailure(req, username);
      return res.status(401).json({ error: "Username atau password salah" });
    }

    const user = normalizeRow(userResult.rows[0]);
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      await applyLoginFailure(req, username);
      return res.status(401).json({ error: "Username atau password salah" });
    }
    clearLoginFailure(req, username);

    const token = generateToken();
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    await db.execute({
      sql: "INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      args: [user.id, token, expiresAt],
    });

    res.cookie(AUTH_COOKIE_NAME, token, getCookieOptions(req));

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    sendServerError(res, err, "auth-login");
  }
});

app.get("/api/auth/me", authenticate, async (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
  });
});

app.get("/api/users", authenticate, authorizeAdmin, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT id, username, role, created_at FROM users ORDER BY id ASC",
    });
    res.json(normalizeRows(result.rows));
  } catch (err) {
    sendServerError(res, err, "users-list");
  }
});

app.delete("/api/users/:id", authenticate, authorizeAdmin, async (req, res) => {
  const targetUserId = Number(req.params.id);
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).json({ error: "ID user tidak valid" });
  }
  if (targetUserId === Number(req.user.id)) {
    return res
      .status(400)
      .json({ error: "Admin tidak bisa menghapus akun sendiri" });
  }

  try {
    const userResult = await db.execute({
      sql: "SELECT id FROM users WHERE id = ? LIMIT 1",
      args: [targetUserId],
    });
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User tidak ditemukan" });
    }

    await db.execute({
      sql: "DELETE FROM auth_tokens WHERE user_id = ?",
      args: [targetUserId],
    });
    await db.execute({
      sql: "DELETE FROM people WHERE user_id = ?",
      args: [targetUserId],
    });
    await db.execute({
      sql: "DELETE FROM users WHERE id = ?",
      args: [targetUserId],
    });

    res.json({ deleted: true, user_id: targetUserId });
  } catch (err) {
    sendServerError(res, err, "users-delete");
  }
});

app.post("/api/auth/logout", authenticate, async (req, res) => {
  try {
    await db.execute({
      sql: "DELETE FROM auth_tokens WHERE token = ?",
      args: [req.token],
    });
    res.clearCookie(AUTH_COOKIE_NAME, { path: "/" });
    res.json({ loggedOut: true });
  } catch (err) {
    sendServerError(res, err, "auth-logout");
  }
});

app.get("/api/people", authenticate, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT * FROM people WHERE user_id = ? ORDER BY nama",
      args: [req.user.id],
    });
    res.json(normalizeRows(result.rows));
  } catch (err) {
    sendServerError(res, err, "people-list");
  }
});

app.post("/api/people", authenticate, async (req, res) => {
  const nama = sanitizeTextInput(req.body?.nama);
  const noRekening = sanitizeRekening(req.body?.no_rekening);

  if (!nama || !noRekening) {
    return res.status(400).json({ error: "nama dan no_rekening wajib diisi" });
  }
  if (nama.length > MAX_PERSON_NAME_LENGTH) {
    return res
      .status(400)
      .json({ error: `nama maksimal ${MAX_PERSON_NAME_LENGTH} karakter` });
  }
  if (
    !/^\d{5,30}$/.test(noRekening) ||
    noRekening.length > MAX_REKENING_LENGTH
  ) {
    return res
      .status(400)
      .json({ error: "no_rekening harus berupa 5-30 digit angka" });
  }

  try {
    const duplicateCheck = await db.execute({
      sql: `SELECT id FROM people
            WHERE user_id = ? AND LOWER(TRIM(nama)) = LOWER(TRIM(?))
            LIMIT 1`,
      args: [req.user.id, nama],
    });

    if (duplicateCheck.rows.length > 0) {
      return res.status(409).json({ error: "Nama teman sudah ada" });
    }

    const insertResult = await db.execute({
      sql: "INSERT INTO people (user_id, nama, no_rekening) VALUES (?, ?, ?) RETURNING id",
      args: [req.user.id, nama, noRekening],
    });
    const inserted = normalizeRow(insertResult.rows[0] || {});
    res.json({ id: inserted.id, nama, no_rekening: noRekening });
  } catch (err) {
    sendServerError(res, err, "people-create");
  }
});

app.delete("/api/people/:id", authenticate, async (req, res) => {
  const peopleId = Number(req.params.id);
  if (!isValidPositiveInt(peopleId)) {
    return res.status(400).json({ error: "ID teman tidak valid" });
  }
  try {
    const deleteResult = await db.execute({
      sql: "DELETE FROM people WHERE id = ? AND user_id = ?",
      args: [peopleId, req.user.id],
    });
    const affectedRows = normalizeValue(deleteResult.rowsAffected || 0);
    if (affectedRows === 0) {
      return res.status(404).json({ error: "Data teman tidak ditemukan" });
    }
    res.json({ deleted: true });
  } catch (err) {
    sendServerError(res, err, "people-delete");
  }
});

app.put("/api/people/:id", authenticate, async (req, res) => {
  const peopleId = Number(req.params.id);
  const nama = sanitizeTextInput(req.body?.nama);
  const noRekening = sanitizeRekening(req.body?.no_rekening);

  if (!isValidPositiveInt(peopleId)) {
    return res.status(400).json({ error: "ID teman tidak valid" });
  }
  if (!nama || !noRekening) {
    return res.status(400).json({ error: "nama dan no_rekening wajib diisi" });
  }
  if (nama.length > MAX_PERSON_NAME_LENGTH) {
    return res
      .status(400)
      .json({ error: `nama maksimal ${MAX_PERSON_NAME_LENGTH} karakter` });
  }
  if (
    !/^\d{5,30}$/.test(noRekening) ||
    noRekening.length > MAX_REKENING_LENGTH
  ) {
    return res
      .status(400)
      .json({ error: "no_rekening harus berupa 5-30 digit angka" });
  }

  try {
    const currentResult = await db.execute({
      sql: "SELECT id FROM people WHERE id = ? AND user_id = ? LIMIT 1",
      args: [peopleId, req.user.id],
    });
    if (currentResult.rows.length === 0) {
      return res.status(404).json({ error: "Data teman tidak ditemukan" });
    }

    const duplicateCheck = await db.execute({
      sql: `SELECT id FROM people
            WHERE user_id = ? AND LOWER(TRIM(nama)) = LOWER(TRIM(?)) AND id != ?
            LIMIT 1`,
      args: [req.user.id, nama, peopleId],
    });

    if (duplicateCheck.rows.length > 0) {
      return res.status(409).json({ error: "Nama teman sudah ada" });
    }

    const updateResult = await db.execute({
      sql: "UPDATE people SET nama = ?, no_rekening = ? WHERE id = ? AND user_id = ?",
      args: [nama, noRekening, peopleId, req.user.id],
    });
    void updateResult;

    res.json({ updated: true, id: peopleId, nama, no_rekening: noRekening });
  } catch (err) {
    sendServerError(res, err, "people-update");
  }
});

app.post("/api/bills", authenticate, async (req, res) => {
  const {
    total_amount,
    discount_amount,
    tax_amount,
    grand_total,
    split_count,
    personBills,
  } = req.body;
  const totalAmount = Number(total_amount);
  const discountAmount = Number(discount_amount ?? 0);
  const taxAmount = Number(tax_amount ?? 0);
  const grandTotal = Number(grand_total);
  const splitCount = Number(split_count);

  if (
    !isFiniteNumber(totalAmount) ||
    !isFiniteNumber(discountAmount) ||
    !isFiniteNumber(taxAmount) ||
    !isFiniteNumber(grandTotal) ||
    totalAmount < 0 ||
    discountAmount < 0 ||
    taxAmount < 0 ||
    grandTotal < 0
  ) {
    return res.status(400).json({
      error: "Nilai total, diskon, pajak, dan grand total harus angka valid",
    });
  }
  if (!isValidPositiveInt(splitCount, MAX_SPLIT_COUNT)) {
    return res
      .status(400)
      .json({ error: `split_count harus bilangan bulat 1-${MAX_SPLIT_COUNT}` });
  }
  if (personBills != null && !Array.isArray(personBills)) {
    return res.status(400).json({ error: "personBills harus berupa array" });
  }
  if (Array.isArray(personBills) && personBills.length > MAX_PERSON_BILLS) {
    return res
      .status(400)
      .json({ error: `personBills maksimal ${MAX_PERSON_BILLS} item` });
  }

  try {
    const billInsertResult = await db.execute({
      sql: "INSERT INTO bills (total_amount, discount_amount, tax_amount, grand_total, split_count) VALUES (?, ?, ?, ?, ?) RETURNING id",
      args: [totalAmount, discountAmount, taxAmount, grandTotal, splitCount],
    });
    const billId = normalizeValue(billInsertResult.rows[0]?.id);

    if (personBills && personBills.length > 0) {
      for (const personBill of personBills) {
        const billItemName = sanitizeTextInput(personBill?.name);
        const billPersonName = sanitizeTextInput(personBill?.personName);
        const billItemAmount = Number(personBill?.amount);
        const rawPersonId = personBill?.personId;
        const billPersonId =
          rawPersonId == null || rawPersonId === ""
            ? null
            : Number(rawPersonId);

        if (!billItemName || billItemName.length > MAX_PERSON_NAME_LENGTH) {
          return res.status(400).json({
            error: `Nama item bill wajib diisi dan maksimal ${MAX_PERSON_NAME_LENGTH} karakter`,
          });
        }
        if (!isFiniteNumber(billItemAmount) || billItemAmount < 0) {
          return res
            .status(400)
            .json({ error: "Nominal item bill harus angka valid" });
        }
        if (billPersonName && billPersonName.length > MAX_PERSON_NAME_LENGTH) {
          return res.status(400).json({
            error: `Nama orang maksimal ${MAX_PERSON_NAME_LENGTH} karakter`,
          });
        }
        if (billPersonId !== null && !isValidPositiveInt(billPersonId)) {
          return res
            .status(400)
            .json({ error: "personId pada bill item tidak valid" });
        }

        await db.execute({
          sql: "INSERT INTO bill_items (bill_id, item_name, item_amount, person_id, person_name) VALUES (?, ?, ?, ?, ?)",
          args: [
            billId,
            billItemName,
            billItemAmount,
            billPersonId,
            billPersonName || null,
          ],
        });
      }
    }

    res.json({ id: billId });
  } catch (err) {
    sendServerError(res, err, "bills-create");
  }
});

app.get("/api/bills", authenticate, async (req, res) => {
  try {
    const result = await db.execute(
      "SELECT * FROM bills ORDER BY created_at DESC LIMIT 50",
    );
    res.json(normalizeRows(result.rows));
  } catch (err) {
    sendServerError(res, err, "bills-list");
  }
});

app.get("/api/bills/:id", authenticate, async (req, res) => {
  const billId = Number(req.params.id);
  if (!isValidPositiveInt(billId)) {
    return res.status(400).json({ error: "ID bill tidak valid" });
  }
  try {
    const result = await db.execute({
      sql: "SELECT * FROM bills WHERE id = ?",
      args: [billId],
    });
    const bill = result.rows[0] ? normalizeRow(result.rows[0]) : null;
    res.json(bill);
  } catch (err) {
    sendServerError(res, err, "bills-detail");
  }
});

app.post("/api/ocr", authenticate, async (req, res) => {
  const imageDataUrl = String(req.body?.imageDataUrl || "");
  if (!imageDataUrl) {
    return res.status(400).json({ error: "imageDataUrl wajib diisi" });
  }
  if (!/^data:image\/[a-zA-Z0-9.+-]+;base64,/.test(imageDataUrl)) {
    return res.status(400).json({ error: "Format gambar tidak valid" });
  }
  if (imageDataUrl.length > MAX_OCR_IMAGE_DATA_URL_LENGTH) {
    return res.status(413).json({ error: "Ukuran gambar terlalu besar" });
  }

  try {
    // Extract base64 data from data URL
    const base64Data = imageDataUrl.replace(
      /^data:image\/[a-zA-Z0-9.+-]+;base64,/,
      "",
    );
    const imageBuffer = Buffer.from(base64Data, "base64");

    const result = await runOcrFromBuffer(imageBuffer);
    if (!result || result.success !== true) {
      return res.status(500).json({
        error: result?.error || "OCR gagal membaca gambar",
      });
    }
    return res.json({ text: String(result.text || "") });
  } catch (err) {
    console.error("OCR Route Error:", err);

    const errMsg = String(err.message || "");

    if (err?.code === "ENOENT") {
      return res.status(500).json({
        error:
          "Tesseract.js tidak ditemukan. Pastikan dependency sudah terinstall.",
      });
    }
    if (errMsg.includes("timeout") || errMsg.includes("Timeout")) {
      return res.status(504).json({
        error:
          "Proses OCR timeout. Coba gunakan gambar dengan resolusi lebih rendah atau format JPEG.",
      });
    }
    if (errMsg.includes("WASM") || errMsg.includes("wasm")) {
      return res.status(500).json({
        error: "OCR gagal dimuat. Coba refresh halaman.",
      });
    }
    if (errMsg.includes("worker") || errMsg.includes("Worker")) {
      return res.status(500).json({
        error: "OCR engine error. Coba beberapa saat lagi.",
      });
    }

    // Log error details untuk debugging
    console.error("OCR Error Details:", {
      name: err.name,
      message: err.message,
      stack: err.stack?.substring(0, 500),
    });

    return res.status(500).json({
      error: "Gagal membaca struk. Pastikan gambar jelas dan coba lagi.",
    });
  }
});

app.use((err, req, res, next) => {
  if (err && String(err.message || "").includes("CORS")) {
    return res.status(403).json({ error: "Origin tidak diizinkan" });
  }
  if (req.path && req.path.startsWith("/api/")) {
    if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
      return res.status(400).json({ error: "Format JSON tidak valid" });
    }
    return sendServerError(res, err, "api-unhandled");
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
    console.error("Gagal inisialisasi database Turso:", err.message);
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
