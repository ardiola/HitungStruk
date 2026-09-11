// Dijalankan sekali saat build di Vercel (lihat "build" script di package.json).
// Mengganti placeholder di public/index.html dengan GEMINI_API_KEY dari
// environment variable, supaya key asli tidak pernah masuk ke git.
//
// PERINGATAN: jangan jalankan ini secara lokal kecuali untuk testing --
// ini akan menulis key asli ke public/index.html di disk. Setelah testing,
// jalankan `git checkout -- public/index.html` supaya tidak ke-commit.

const fs = require("fs");
const path = require("path");

const PLACEHOLDER = "PASTE_YOUR_GEMINI_API_KEY_HERE";
const filePath = path.join(__dirname, "..", "public", "index.html");

const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
  console.warn(
    "[inject-gemini-key] GEMINI_API_KEY tidak diset, public/index.html tetap pakai placeholder.",
  );
  process.exit(0);
}

const html = fs.readFileSync(filePath, "utf8");
if (!html.includes(PLACEHOLDER)) {
  console.warn(
    "[inject-gemini-key] Placeholder tidak ditemukan di public/index.html, lewati.",
  );
  process.exit(0);
}

fs.writeFileSync(filePath, html.split(PLACEHOLDER).join(apiKey));
console.log("[inject-gemini-key] GEMINI_API_KEY berhasil disuntikkan ke public/index.html");
