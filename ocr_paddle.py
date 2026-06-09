import base64
import json
import re
import sys


def _extract_box_metrics(box):
    if not isinstance(box, (list, tuple)) or len(box) == 0:
        return 0.0, 0.0, 0.0
    xs = []
    ys = []
    for point in box:
        if isinstance(point, (list, tuple)) and len(point) >= 2:
            try:
                xs.append(float(point[0]))
                ys.append(float(point[1]))
            except (TypeError, ValueError):
                continue
    if not xs or not ys:
        return 0.0, 0.0, 0.0
    x_center = sum(xs) / len(xs)
    y_center = sum(ys) / len(ys)
    height = max(ys) - min(ys)
    return x_center, y_center, height


def _flatten_text_boxes(result):
    entries = []
    if not isinstance(result, list):
        return entries

    for block in result:
        if not isinstance(block, list):
            continue
        for item in block:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            box = item[0]
            info = item[1]
            if not isinstance(info, (list, tuple)) or len(info) < 1:
                continue
            text = str(info[0] or "").strip()
            if not text:
                continue
            x_center, y_center, height = _extract_box_metrics(box)
            entries.append(
                {
                    "x": x_center,
                    "y": y_center,
                    "h": height,
                    "text": text,
                }
            )
    return entries


def _group_into_lines(entries):
    if not entries:
        return []
    entries = sorted(entries, key=lambda item: (item["y"], item["x"]))
    avg_height = sum(item["h"] for item in entries if item["h"] > 0) / max(
        1, len([item for item in entries if item["h"] > 0])
    )
    row_threshold = max(10.0, avg_height * 0.55)
    rows = []
    current_row = [entries[0]]
    current_row_y = entries[0]["y"]

    for item in entries[1:]:
        if abs(item["y"] - current_row_y) <= row_threshold:
            current_row.append(item)
            current_row_y = (current_row_y * (len(current_row) - 1) + item["y"]) / len(
                current_row
            )
        else:
            rows.append(current_row)
            current_row = [item]
            current_row_y = item["y"]
    rows.append(current_row)

    lines = []
    for row in rows:
        ordered = sorted(row, key=lambda item: item["x"])
        line_text = " ".join(item["text"] for item in ordered).strip()
        if line_text:
            lines.append(line_text)
    return lines


def _has_price(line):
    return bool(
        re.search(r"(?:rp\s*)?[0-9OoIlS.,]*[0-9][0-9OoIlS.,]{2,}", line, re.IGNORECASE)
    )


def _has_alpha(line):
    return bool(re.search(r"[a-zA-Z]", line))


def _merge_lines_for_items(lines):
    """Merge item name with price. Keep items separate if already complete."""
    merged = []
    i = 0
    while i < len(lines):
        current = lines[i]

        current_has_alpha = _has_alpha(current)
        current_has_price = _has_price(current)

        # If line has both alpha and price, it's a complete item - keep separate
        if current_has_alpha and current_has_price:
            merged.append(current)
            i += 1
            continue

        # If line has only alpha, look for price in next lines
        if current_has_alpha and not current_has_price:
            j = i + 1
            while (
                j < len(lines) and not _has_alpha(lines[j]) and not _has_price(lines[j])
            ):
                j += 1
            if j < len(lines) and _has_price(lines[j]) and not _has_alpha(lines[j]):
                skipped = lines[i + 1 : j]
                merged.append(" ".join([current] + skipped + [lines[j]]))
                i = j + 1
                continue

        # If line has only price, look for alpha in next lines
        if current_has_price and not current_has_alpha:
            j = i + 1
            while (
                j < len(lines) and not _has_alpha(lines[j]) and not _has_price(lines[j])
            ):
                j += 1
            if j < len(lines) and _has_alpha(lines[j]) and not _has_price(lines[j]):
                skipped = lines[i + 1 : j]
                merged.append(" ".join([lines[j]] + skipped + [current]))
                i = j + 1
                continue

        merged.append(current)
        i += 1
    return merged


def decode_data_url(image_data_url):
    if not isinstance(image_data_url, str):
        raise ValueError("imageDataUrl harus berupa string")
    if not image_data_url.startswith("data:image/"):
        raise ValueError("Format gambar tidak didukung")

    parts = image_data_url.split(",", 1)
    if len(parts) != 2:
        raise ValueError("Format data URL tidak valid")

    try:
        return base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise ValueError("Base64 gambar tidak valid") from exc


def preprocess_image(image):
    """Minimal preprocessing for speed."""
    import cv2

    height, width = image.shape[:2]

    # Only resize if very small
    if height < 300 or width < 300:
        scale = max(300 / height, 300 / width)
        new_width = int(width * scale)
        new_height = int(height * scale)
        image = cv2.resize(
            image, (new_width, new_height), interpolation=cv2.INTER_CUBIC
        )

    return image


# Cache OCR model for reuse
_ocr_model = None


def get_ocr_model():
    global _ocr_model
    if _ocr_model is None:
        from paddleocr import PaddleOCR

        _ocr_model = PaddleOCR(
            use_angle_cls=True,
            lang="en",
            show_log=False,
            use_gpu=False,
            det_db_thresh=0.5,
            rec_batch_num=8,
        )
    return _ocr_model


def run_ocr(image_bytes):
    import cv2
    import numpy as np

    np_buffer = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(np_buffer, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Gagal memuat gambar")

    # Minimal preprocessing
    image = preprocess_image(image)

    # Use cached OCR model
    ocr = get_ocr_model()
    result = ocr.ocr(image, cls=True)
    entries = _flatten_text_boxes(result)
    lines = _group_into_lines(entries)
    merged_lines = _merge_lines_for_items(lines)
    return "\n".join(merged_lines)


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        image_data_url = payload.get("imageDataUrl")
        image_bytes = decode_data_url(image_data_url)
        text = run_ocr(image_bytes)
        print(json.dumps({"success": True, "text": text}, ensure_ascii=False))
    except Exception as exc:
        print(
            json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False),
        )


if __name__ == "__main__":
    main()
