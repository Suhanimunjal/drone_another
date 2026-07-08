#!/usr/bin/env python3
"""
Offline, one-time ingestion script for the drone_reference table.

Usage:
    python ingest_reference.py

Scans uploads/drone_references/ for image files + sidecar .json metadata,
computes CLIP embeddings, and populates the drone_reference table in forensics.db.

Sidecar JSON example (drone_references/redkite.json next to redkite.jpg):
{
  "manufacturer": "Blue Bear Systems Research",
  "model": "RedKite",
  "aliases": "RedKite UAV,RedKite Drone",
  "category": "fixed-wing",
  "wingspan_m": 3.0,
  "weight_kg": 12.5,
  "endurance_min": 360,
  "payload_notes": "EO/IR gimbal",
  "typical_operators": "military,government",
  "source_url": "https://www.blue-bear.co.uk/redkite"
}
"""

import os, sys, json, uuid, glob
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
from PIL import Image as PILImage

# ── DB setup (same as backend_server.py) ─────────────────────────────────
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
REFERENCE_DIR = os.path.join(UPLOAD_DIR, "drone_references")
os.makedirs(REFERENCE_DIR, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    return conn


# ── CLIP setup (lazy load) ──────────────────────────────────────────────
_clip_model = None
_clip_processor = None


def _get_clip():
    global _clip_model, _clip_processor
    if _clip_model is None:
        from transformers import CLIPModel, CLIPProcessor
        print("Loading CLIP model (first time may download ~600MB)...")
        _clip_model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32")
        _clip_processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
        print("CLIP model loaded.")
    return _clip_model, _clip_processor


def compute_embedding(image_path):
    import torch as _torch
    import numpy as np
    model, processor = _get_clip()
    image = PILImage.open(image_path).convert("RGB")
    inputs = processor(images=image, return_tensors="pt")
    with _torch.no_grad():
        outputs = model.get_image_features(**inputs)
        if hasattr(outputs, "pooler_output"):
            tensor = outputs.pooler_output
        elif hasattr(outputs, "numpy"):
            tensor = outputs
        else:
            tensor = outputs[0]
    return tensor.numpy().flatten().astype(np.float32)


# ── Supported image extensions ──────────────────────────────────────────
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff", ".tif"}


def ingest_all():
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    ingested = 0
    skipped = 0

    # Find all image files in reference directory
    image_files = []
    for ext in IMAGE_EXTS:
        image_files.extend(glob.glob(os.path.join(REFERENCE_DIR, "*" + ext)))
        image_files.extend(glob.glob(os.path.join(REFERENCE_DIR, "*" + ext.upper())))

    if not image_files:
        print(f"No reference images found in {REFERENCE_DIR}")
        print("Place drone reference images (jpg/png) with sidecar .json files there.")
        conn.close()
        return

    print(f"Found {len(image_files)} image(s) in {REFERENCE_DIR}")

    for img_path in sorted(image_files):
        base = os.path.splitext(img_path)[0]
        json_path = base + ".json"
        img_name = os.path.basename(img_path)

        # Read sidecar JSON
        if not os.path.isfile(json_path):
            print(f"  SKIP {img_name} — no sidecar {os.path.basename(json_path)}")
            skipped += 1
            continue

        with open(json_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        manufacturer = meta.get("manufacturer", "").strip()
        model = meta.get("model", "").strip()
        if not manufacturer or not model:
            print(f"  SKIP {img_name} — missing manufacturer/model in JSON")
            skipped += 1
            continue

        # Compute embedding
        print(f"  Computing embedding for {img_name} ({manufacturer} {model})...", end=" ", flush=True)
        try:
            embedding = compute_embedding(img_path)
        except Exception as e:
            print(f"FAILED: {e}")
            skipped += 1
            continue

        # Copy image to be stored locally (if not already in REFERENCE_DIR)
        # The image stays in place — reference_image_path stores its relative path

        ref_id = str(uuid.uuid4())
        aliases = meta.get("aliases", "")
        category = meta.get("category", "")
        wingspan_m = meta.get("wingspan_m")
        weight_kg = meta.get("weight_kg")
        endurance_min = meta.get("endurance_min")
        payload_notes = meta.get("payload_notes", "")
        typical_operators = meta.get("typical_operators", "")
        source_url = meta.get("source_url", "")

        # Relative path from project root
        rel_path = os.path.relpath(img_path, os.path.dirname(os.path.abspath(__file__)))

        conn.execute(
            """INSERT OR REPLACE INTO drone_reference
               (id, manufacturer, model, aliases, category, reference_image_path,
                embedding_vector, wingspan_m, weight_kg, endurance_min,
                payload_notes, typical_operators, source_url, ingested_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ref_id, manufacturer, model, aliases, category, rel_path,
                embedding.tobytes(), wingspan_m, weight_kg, endurance_min,
                payload_notes, typical_operators, source_url, now
            )
        )
        conn.commit()
        print(f"OK (id={ref_id[:8]}…)")
        ingested += 1

    conn.close()
    print(f"\nDone. Ingested: {ingested}, Skipped: {skipped}")


if __name__ == "__main__":
    ingest_all()
