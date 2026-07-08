#!/usr/bin/env python3
"""
drone_image_matcher.py

Matches an uploaded "physical evidence" photo against a reference database
of known drone records, where each record can have an arbitrary set of
attributes (dynamic schema — no hardcoded fields beyond id/model/manufacturer/
photo paths).

DESIGN
-------
- Reference records are plain dicts:
    {
        "id": "VT-FP-V2",
        "model_name": "VT-FP-V2",
        "manufacturer": "Vireo Tech",
        "photo_paths": ["/path/to/vt_fp_v2_front.jpg", "/path/to/vt_fp_v2_top.jpg"],
        "attributes": {
            "Type": "Quadcopter",
            "Category": "Professional",
            "Country": "China",
            "Endurance": "40 min",
            ... (anything at all — this dict is never touched by matching
                 logic, it's purely passed through to the UI)
        }
    }
  This script never assumes which attribute keys exist — it only ever reads
  id/model_name/manufacturer/photo_paths for matching purposes, and returns
  the full `attributes` dict untouched for the frontend to render dynamically.

- Matching uses CLIP image embeddings (robust to different angles, lighting,
  backgrounds — appropriate for product-style reference photos vs. a real
  evidence photo). Falls back to perceptual hashing (imagehash) if
  torch/open_clip isn't installed, so this still runs in a lightweight
  environment, just with lower match accuracy.

- Embeddings are computed fresh for reference photos each time
  build_reference_index() is called rather than being baked into a static
  file, so adding/editing/removing records and re-running the index build
  immediately reflects in matching — no stale cache.

DEPENDENCIES
-------------
Preferred (accurate):   pip install torch open_clip_torch pillow
Fallback (lightweight): pip install imagehash pillow

USAGE
------
    from drone_image_matcher import build_reference_index, match_photo

    records = load_records_from_your_db()   # your existing DB query
    index = build_reference_index(records)

    result = match_photo("/path/to/uploaded_evidence_photo.jpg", index,
                          threshold=0.80)

    if result["matched"]:
        record = result["record"]           # full record incl. attributes
        score  = result["score"]
        keywords = [record["manufacturer"], record["model_name"]]
        # -> use keywords to trigger the "find more info" web lookup
    else:
        # -> fall through to reverse image search (Yandex/Bing links)
        pass
"""

import os
from typing import List, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Backend selection: CLIP preferred, perceptual hash fallback
# ---------------------------------------------------------------------------
_BACKEND = None

try:
    import torch
    import open_clip
    from PIL import Image

    _device = "cuda" if torch.cuda.is_available() else "cpu"
    _model, _, _preprocess = open_clip.create_model_and_transforms(
        "ViT-B-32", pretrained="openai"
    )
    _model.to(_device).eval()
    _BACKEND = "clip"
    print("[drone_image_matcher] Using CLIP backend (ViT-B-32) on", _device)
except ImportError:
    try:
        import imagehash
        from PIL import Image
        _BACKEND = "phash"
        print("[drone_image_matcher] torch/open_clip not found — "
              "falling back to perceptual hashing (lower accuracy). "
              "Install torch + open_clip_torch for real embedding matching.")
    except ImportError:
        raise ImportError(
            "Neither (torch + open_clip_torch) nor imagehash is installed. "
            "Run: pip install torch open_clip_torch pillow   "
            "(recommended)  or  pip install imagehash pillow  (fallback)"
        )


# ---------------------------------------------------------------------------
# Embedding computation
# ---------------------------------------------------------------------------
def _embed_clip(image_path: str):
    img = Image.open(image_path).convert("RGB")
    tensor = _preprocess(img).unsqueeze(0).to(_device)
    with torch.no_grad():
        feat = _model.encode_image(tensor)
        feat = feat / feat.norm(dim=-1, keepdim=True)
    return feat.squeeze(0).cpu().numpy()


def _embed_phash(image_path: str):
    img = Image.open(image_path).convert("RGB")
    return imagehash.phash(img, hash_size=16)  # 256-bit hash, decent detail


def compute_embedding(image_path: str):
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Reference/query image not found: {image_path}")
    if _BACKEND == "clip":
        return _embed_clip(image_path)
    else:
        return _embed_phash(image_path)


def _similarity(emb_a, emb_b) -> float:
    """
    Returns a similarity score in [0, 1], 1 = identical, regardless of
    backend, so downstream threshold logic doesn't need to know which
    backend is active.
    """
    if _BACKEND == "clip":
        import numpy as np
        cos_sim = float(np.dot(emb_a, emb_b))  # already normalized
        return max(0.0, min(1.0, (cos_sim + 1) / 2))  # map [-1,1] -> [0,1]
    else:
        # phash: hamming distance, smaller = more similar. Normalize to
        # [0,1] similarity using hash bit-length.
        max_bits = len(emb_a.hash.flatten()) if hasattr(emb_a, "hash") else 256
        dist = emb_a - emb_b  # imagehash overloads subtraction as hamming distance
        return max(0.0, 1.0 - (dist / max_bits))


# ---------------------------------------------------------------------------
# Index building — call this fresh whenever you want matching to reflect
# the current state of the reference database (e.g. on each request, or
# on a cheap in-memory cache invalidated whenever a record is added/edited).
# ---------------------------------------------------------------------------
def build_reference_index(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    records: list of dicts as described in the module docstring.
    Returns an index: list of {"record": ..., "photo_path": ..., "embedding": ...}
    with ONE entry per reference photo (a record with 3 photos yields 3
    index entries, all pointing back at the same record — this lets a
    match on ANY reference angle/photo count as a match for that record).
    """
    index = []
    for record in records:
        photo_paths = record.get("photo_paths") or []
        if isinstance(photo_paths, str):  # tolerate single-string field too
            photo_paths = [photo_paths]
        for p in photo_paths:
            try:
                emb = compute_embedding(p)
            except FileNotFoundError as e:
                print(f"[drone_image_matcher] WARNING: {e} — skipping this photo")
                continue
            index.append({"record": record, "photo_path": p, "embedding": emb})
    print(f"[drone_image_matcher] Reference index built: "
          f"{len(index)} photos across {len(records)} records "
          f"(backend={_BACKEND})")
    return index


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def match_photo(
    query_image_path: str,
    index: List[Dict[str, Any]],
    threshold: float = 0.80,
    top_k: int = 5,
) -> Dict[str, Any]:
    """
    Returns:
    {
        "matched": bool,
        "score": float or None,           # best score found
        "record": dict or None,           # full matched record (with attributes)
        "matched_photo": str or None,      # which reference photo scored best
        "top_candidates": [                # for UI transparency / manual review
            {"record_id": ..., "model_name": ..., "score": ..., "photo_path": ...},
            ...
        ]
    }
    """
    if not index:
        return {
            "matched": False, "score": None, "record": None,
            "matched_photo": None, "top_candidates": [],
            "note": "Reference index is empty — no records to match against.",
        }

    query_emb = compute_embedding(query_image_path)

    scored = []
    for entry in index:
        score = _similarity(query_emb, entry["embedding"])
        scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    top_candidates = [
        {
            "record_id": e["record"].get("id"),
            "model_name": e["record"].get("model_name"),
            "manufacturer": e["record"].get("manufacturer"),
            "score": round(s, 4),
            "photo_path": e["photo_path"],
        }
        for s, e in scored[:top_k]
    ]

    best_score, best_entry = scored[0]
    if best_score >= threshold:
        return {
            "matched": True,
            "score": round(best_score, 4),
            "record": best_entry["record"],
            "matched_photo": best_entry["photo_path"],
            "top_candidates": top_candidates,
        }
    else:
        return {
            "matched": False,
            "score": round(best_score, 4),
            "record": None,
            "matched_photo": None,
            "top_candidates": top_candidates,
            "note": f"Best match scored {best_score:.2f}, below threshold "
                    f"{threshold:.2f} — falling through to reverse image "
                    f"search.",
        }


# ---------------------------------------------------------------------------
# Self-test / example when run directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python drone_image_matcher.py <query_image> "
              "<reference_photo_1> [<reference_photo_2> ...]")
        print("Runs a quick similarity test using the first reference "
              "photo as a fake single-record database.")
        sys.exit(0)

    query = sys.argv[1]
    refs = sys.argv[2:]
    fake_records = [{
        "id": "TEST-1", "model_name": "Test Model", "manufacturer": "Test Co",
        "photo_paths": refs, "attributes": {"Note": "self-test record"},
    }]
    idx = build_reference_index(fake_records)
    result = match_photo(query, idx, threshold=0.80)
    print(result)
