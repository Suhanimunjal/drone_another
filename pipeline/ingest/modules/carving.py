"""C9 — Data Carving.

Scans files for known file headers (JPEG, PNG, ZIP, PDF, etc.) at arbitrary
offsets. Useful for recovering embedded or deleted files from binary blobs.
"""

import os
import struct
from ..base import IngestModule, Artifact

MAX_CARVE_SIZE = 50 * 1024 * 1024  # skip files > 50 MB

# (name, extension, magic_bytes, max_size)
SIGNATURES = [
    ("JPEG", ".jpg", bytes([0xFF, 0xD8, 0xFF]), 50 * 1024 * 1024),
    ("PNG", ".png", bytes([0x89, 0x50, 0x4E, 0x47]), 50 * 1024 * 1024),
    ("GIF", ".gif", b"GIF8", 10 * 1024 * 1024),
    ("ZIP", ".zip", bytes([0x50, 0x4B, 0x03, 0x04]), 200 * 1024 * 1024),
    ("PDF", ".pdf", b"%PDF", 100 * 1024 * 1024),
    ("RIFF", ".avi/.wav", b"RIFF", 200 * 1024 * 1024),
    ("MP4", ".mp4", bytes([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]), 200 * 1024 * 1024),
    ("BMP", ".bmp", b"BM", 50 * 1024 * 1024),
    ("TIFF_LE", ".tiff", bytes([0x49, 0x49, 0x2A, 0x00]), 50 * 1024 * 1024),
    ("TIFF_BE", ".tiff", bytes([0x4D, 0x4D, 0x00, 0x2A]), 50 * 1024 * 1024),
    ("DNG", ".dng", bytes([0x49, 0x49, 0x2A, 0x00]), 50 * 1024 * 1024),
]

CARVE_DIR = "carved"


def _find_signatures(data):
    """Find all signature matches in data. Returns list of (name, ext, offset)."""
    hits = []
    for name, ext, magic, _ in SIGNATURES:
        offset = 0
        while True:
            pos = data.find(magic, offset)
            if pos == -1:
                break
            # Skip matches at position 0 (that's the file's own header, not embedded)
            if pos > 0:
                hits.append((name, ext, pos))
            offset = pos + 1
    return hits


def _is_binary(path):
    """Quick check: if the file has null bytes or high-bit bytes, treat as binary."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        return b"\x00" in head or any(b > 127 for b in head[:256])
    except Exception:
        return True


class CarvingModule(IngestModule):
    name = "carving"
    depends_on = []
    applies_to = "all_files"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        file_path = file_manifest_row.get("extracted_path")
        case_id = file_manifest_row.get("case_id")
        file_id = file_manifest_row.get("id")
        rel_path = file_manifest_row.get("path", "")

        if not file_path or not os.path.isfile(file_path):
            return []

        try:
            size = os.path.getsize(file_path)
            if size > MAX_CARVE_SIZE:
                return []
        except OSError:
            return []

        # Skip obvious text files
        if not _is_binary(file_path):
            return []

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception:
            return []

        hits = _find_signatures(data)
        if not hits:
            return []

        output_dir = (case_context or {}).get("output_dir", "")
        carve_dir = os.path.join(output_dir, CARVE_DIR)
        os.makedirs(carve_dir, exist_ok=True)

        results = []
        seen_offsets = set()

        for name, ext, offset in hits:
            if offset in seen_offsets:
                continue
            seen_offsets.add(offset)

            # Try to find the end offset for the carved fragment
            end_offset = min(offset + 1024 * 1024, len(data))  # default 1 MB max

            # For JPEG/JFIF, look for end marker FFD9
            if name == "JPEG":
                end_pos = data.find(bytes([0xFF, 0xD9]), offset)
                if end_pos != -1 and end_pos > offset:
                    end_offset = end_pos + 2

            carve_name = f"{os.path.splitext(os.path.basename(rel_path))[0]}_offset{offset}{ext}"
            carve_path = os.path.join(carve_dir, carve_name)

            try:
                with open(carve_path, "wb") as f:
                    f.write(data[offset:end_offset])
            except Exception:
                continue

            results.append(Artifact(
                artifact_type="TSK_CARVED_FILE",
                case_id=case_id,
                module_name=self.name,
                file_id=file_id,
                severity="medium",
                title=f"Carved {name} @ offset {offset}",
                description=f"Embedded {name} found at byte {offset} in {os.path.basename(rel_path)} ({end_offset - offset} bytes)",
                byte_offset=offset,
                details={
                    "format": name,
                    "carve_path": carve_path,
                    "carve_size": end_offset - offset,
                    "source_file": rel_path,
                    "source_file_offset": offset,
                },
            ))

        return results
