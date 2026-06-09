const Tesseract = require("tesseract.js");
const sharp = require("sharp");

let _ocrWorker = null;
let _workerInitPromise = null;

const OCR_TIMEOUT_MS = 25000; // 25 detik timeout untuk serverless

// Sharp preprocessing - V5 (original V2 pipeline, PNG output, no threshold)
// Pipeline identik dengan V2 original yang sudah terbukti, hanya ganti JPEG -> PNG
async function preprocessImageSharp(buffer) {
  console.log("Sharp: Starting preprocessing v5...");
  const startTime = Date.now();

  try {
    const metadata = await sharp(buffer).metadata();
    console.log("Sharp: Original size:", metadata.width, "x", metadata.height);

    // Crop hanya kolom kanan (harga)
    // Sesuaikan persentase sesuai struk kamu
    // const cropWidth = Math.floor(width * 0.42); // Ambil 38% dari kanan
    // const leftPosition = width - cropWidth; // Mulai dari kanan
    const cropPercentFromRight = 0.37; // Coba ubah antara 0.34 - 0.40
    const cropWidth = Math.floor(width * cropPercentFromRight);
    const leftPosition = width - cropWidth;

    const result = await sharp(buffer)
      .rotate()
      .extract({
        left: leftPosition,
        top: Math.floor(height * 0.22), // Mulai dari bawah header
        width: cropWidth,
        height: Math.floor(height * 0.65), // Potong bagian bawah
      })
      .resize({ width: 1400 }) // Resize kolom harga
      .greyscale()
      .normalize({ lower: 8, upper: 92 })
      .modulate({
        brightness: 1.28,
        contrast: 2.45,
      })
      .median(5)
      .threshold(72) // Threshold sangat tinggi
      .sharpen({ sigma: 2.0 })
      .toBuffer();
    // .extract({
    //   left: leftPosition, // mulai dari posisi ini
    //   top: 0,
    //   width: cropWidth,
    //   height: height,
    // })
    // .resize(2000, 2500, { fit: "inside", withoutEnlargement: true })
    // .greyscale()
    // .normalize({ lower: 10, upper: 90 })
    // .clahe({
    //   // Local contrast — sangat membantu struk
    //   width: 8,
    //   height: 8,
    //   limit: 4,
    // })
    // .modulate({
    //   brightness: 1.25,
    //   contrast: 2.3,
    // })
    // .median(5)
    // .threshold(65)
    // .sharpen({ sigma: 2.0, m1: 2.0, m2: 4.0, x1: 2, y2: 10, y3: 20 })
    // .sharpen({ sigma: 0.8, m1: 0.5, m2: 1.5 })
    // .png({ compressionLevel: 9, adaptiveFiltering: false })
    // .toBuffer();
    // .rotate()
    // .resize(2000, 2500, { fit: "inside", withoutEnlargement: true })
    // .grayscale()
    // .normalize()
    // // .gamma(0.8)
    // // .linear(1.5, -30)
    // .sharpen({ sigma: 2.0, m1: 2.0, m2: 4.0, x1: 2, y2: 10, y3: 20 })
    // .sharpen({ sigma: 0.8, m1: 0.5, m2: 1.5 })
    // // .median(3)
    // // .linear(1.2, -5)
    // .png({ compressionLevel: 9, adaptiveFiltering: false })
    // .toBuffer();

    const duration = Date.now() - startTime;
    console.log(
      "Sharp: Preprocessing v5 done in",
      duration,
      "ms, output size:",
      result.length,
      "bytes",
    );

    return result;
  } catch (err) {
    console.error("Sharp: Preprocessing v5 failed:", err.message);
    return buffer;
  }
}

function withTimeout(promise, timeoutMs, errorMessage) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(errorMessage)), timeoutMs),
    ),
  ]);
}

async function getOcrWorker() {
  if (_ocrWorker && _ocrWorker.recognize) {
    console.log("OCR: Using cached worker");
    return _ocrWorker;
  }

  if (_workerInitPromise) {
    console.log("OCR: Waiting for existing init...");
    return _workerInitPromise;
  }

  console.log("OCR: Initializing new worker...");

  _workerInitPromise = withTimeout(
    Tesseract.createWorker("eng", 1, {
      logger: (m) => {
        console.log("OCR Worker:", m.status);
      },
      errorHandler: (err) => console.error("OCR Worker Error:", err),
    }),
    OCR_TIMEOUT_MS,
    "OCR worker initialization timeout",
  )
    .then((worker) => {
      console.log("OCR: Setting optimized parameters...");
      worker.setParameters({
        tessedit_ocr_engine_mode: "3",
        tessedit_pageseg_mode: "6",
        preserve_interword_spaces: "1",
      });
      console.log("OCR: Worker initialized successfully");
      _ocrWorker = worker;
      return worker;
    })
    .catch((err) => {
      console.error("OCR: Worker init failed:", err.message);
      _workerInitPromise = null;
      _ocrWorker = null;
      throw err;
    });

  return _workerInitPromise;
}

async function resetOcrWorker() {
  console.log("OCR: Resetting worker...");
  try {
    if (_ocrWorker) {
      await _ocrWorker.terminate();
    }
  } catch (e) {
    console.error("OCR: Error terminating worker:", e);
  }
  _ocrWorker = null;
  _workerInitPromise = null;
  console.log("OCR: Worker reset complete");
}

function _extract_box_metrics(box) {
  if (!box || typeof box !== "object") return { x: 0, y: 0, h: 0 };
  const { bbox, height } = box;
  if (!bbox) return { x: 0, y: 0, h: 0 };
  return {
    x: (bbox.x0 + bbox.x1) / 2,
    y: (bbox.y0 + bbox.y1) / 2,
    h: height || bbox.y1 - bbox.y0,
  };
}

function _flatten_text_boxes(result) {
  const entries = [];
  if (!result || !result.data) {
    console.log("OCR: result.data is missing");
    return entries;
  }

  if (result.data.lines && Array.isArray(result.data.lines)) {
    console.log("OCR: Found lines:", result.data.lines.length);
    for (const line of result.data.lines) {
      if (!line.text || !line.text.trim()) continue;
      const { x, y, h } = _extract_box_metrics(line);
      entries.push({ x, y, h, text: line.text.trim() });
    }
  } else if (result.data.words && Array.isArray(result.data.words)) {
    console.log("OCR: No lines, found words:", result.data.words.length);
    for (const word of result.data.words) {
      if (!word.text || !word.text.trim()) continue;
      const { x, y, h } = _extract_box_metrics(word);
      entries.push({ x, y, h, text: word.text.trim() });
    }
  } else if (result.data.paragraphs && Array.isArray(result.data.paragraphs)) {
    console.log("OCR: Found paragraphs:", result.data.paragraphs.length);
    for (const para of result.data.paragraphs) {
      if (!para.text || !para.text.trim()) continue;
      const { x, y, h } = _extract_box_metrics(para);
      entries.push({ x, y, h, text: para.text.trim() });
    }
  } else if (result.data.text) {
    console.log("OCR: No lines/words/paragraphs, using raw text");
    const text = result.data.text;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i].trim();
      if (lineText) {
        entries.push({ x: 0, y: i * 20, h: 20, text: lineText });
      }
    }
  } else {
    console.log("OCR: No recognizable structure in result.data");
    console.log("OCR: result.data keys:", Object.keys(result.data || {}));
  }

  return entries;
}

function _group_into_lines(entries) {
  if (!entries || entries.length === 0) return [];
  entries = entries.sort((a, b) => a.y - b.y);

  const avgHeight =
    entries.reduce((sum, e) => sum + (e.h || 0), 0) / entries.length;
  const rowThreshold = Math.max(8, avgHeight * 0.5);

  const rows = [];
  let currentRow = [entries[0]];
  let lastY = entries[0].y;

  for (let i = 1; i < entries.length; i++) {
    const gap = entries[i].y - lastY;
    if (gap <= rowThreshold) {
      currentRow.push(entries[i]);
      lastY = entries[i].y;
    } else {
      rows.push(currentRow);
      currentRow = [entries[i]];
      lastY = entries[i].y;
    }
  }
  rows.push(currentRow);

  return rows.map((row) => {
    row.sort((a, b) => a.x - b.x);
    return row.map((e) => e.text).join(" ");
  });
}

function _has_price(line) {
  return /Rp\s*?[0-9.,]+|[0-9]{1,3}(?:[.,][0-9]{3})+/i.test(line);
}

function _has_alpha(line) {
  return /[a-zA-Z]/.test(line);
}

function _merge_lines_for_items(lines) {
  const merged = [];
  let i = 0;

  while (i < lines.length) {
    const current = lines[i];
    let j = i + 1;

    while (
      j < lines.length &&
      !_has_alpha(lines[j]) &&
      !_has_price(lines[j]) &&
      j < i + 4
    ) {
      j++;
    }

    if (j < lines.length) {
      const nextLine = lines[j];
      const currentHasAlpha = _has_alpha(current);
      const currentHasPrice = _has_price(current);
      const nextHasAlpha = _has_alpha(nextLine);
      const nextHasPrice = _has_price(nextLine);

      if (currentHasAlpha && currentHasPrice) {
        merged.push(current);
        i++;
        continue;
      }

      if (nextHasAlpha && nextHasPrice) {
        merged.push(current);
        i++;
        continue;
      }

      if (
        currentHasAlpha &&
        !currentHasPrice &&
        nextHasPrice &&
        !nextHasAlpha
      ) {
        merged.push(`${current} ${nextLine}`);
        i = j + 1;
        continue;
      }

      if (
        currentHasPrice &&
        !currentHasAlpha &&
        nextHasAlpha &&
        !nextHasPrice
      ) {
        merged.push(`${nextLine} ${current}`);
        i = j + 1;
        continue;
      }
    }

    merged.push(current);
    i++;
  }

  return merged;
}

// Helper: buffer -> data URL -> recognize -> merge lines
async function _ocr_buffer(worker, buffer, label) {
  try {
    const firstByte = buffer[0];
    const secondByte = buffer[1];
    let mimeType = "image/jpeg";
    if (firstByte === 0x89 && secondByte === 0x50) mimeType = "image/png";
    else if (firstByte === 0xff && secondByte === 0xd8) mimeType = "image/jpeg";

    const dataUrl = `data:${mimeType};base64,${buffer.toString("base64")}`;
    console.log("OCR: Recognizing " + label + " (" + buffer.length + " bytes)");

    const result = await withTimeout(
      worker.recognize(dataUrl),
      OCR_TIMEOUT_MS,
      "OCR timeout: " + label,
    );

    const entries = _flatten_text_boxes(result);
    console.log("OCR: " + label + " entries:", entries.length);
    const lines = _group_into_lines(entries);
    const mergedLines = _merge_lines_for_items(lines);
    console.log("OCR: " + label + " merged lines:", mergedLines.length);

    return mergedLines.join("\n");
  } catch (err) {
    console.warn("OCR: " + label + " failed:", err.message);
    return "";
  }
}

async function runOcr(imageBuffer) {
  let worker = null;

  try {
    console.log("OCR: Starting OCR process...");

    // Siapkan 2 varian: Sharp-preprocessed + original
    const buffers = [];

    // Varian 1: Sharp preprocessing
    try {
      console.log("OCR: Preprocessing image with Sharp...");
      const sharpBuf = await preprocessImageSharp(imageBuffer);
      buffers.push({ buffer: sharpBuf, label: "sharp-v5" });
    } catch (sharpError) {
      console.warn("OCR: Sharp preprocessing failed:", sharpError.message);
    }

    // Varian 2: Original tanpa preprocessing (fallback)
    buffers.push({ buffer: imageBuffer, label: "original" });

    console.log("OCR: Will try " + buffers.length + " image variants");

    worker = await withTimeout(
      getOcrWorker(),
      OCR_TIMEOUT_MS,
      "OCR worker initialization timeout",
    );

    if (!worker) {
      throw new Error("Failed to get OCR worker");
    }

    // OCR semua varian, pilih teks terpanjang
    let bestText = "";
    for (const { buffer, label } of buffers) {
      const text = await _ocr_buffer(worker, buffer, label);
      if (text.length > bestText.length) {
        bestText = text;
      }
    }

    console.log(
      "OCR: Best text length:",
      bestText.length,
      "chars, preview:",
      bestText.substring(0, 200),
    );

    return bestText;
  } catch (error) {
    console.error("OCR Error:", error.message);
    await resetOcrWorker();
    throw new Error("OCR processing failed: " + error.message);
  }
}

module.exports = { runOcr };
