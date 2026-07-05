"""file_tree_exporter.py

Builds a JSON file-tree of an extracted filesystem for web display,
and provides the files for download.

API endpoints that use this:
    GET /api/extraction/file-tree   →  { tree: {...}, total_files: N, total_size: N }
    GET /api/extraction/files       →  [{ path, size, sha1, type }, ...]
    GET /api/extraction/download/<path>  →  file download
    GET /api/extraction/download-all     →  zip download
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any


def compute_sha1(filepath: str | Path) -> str:
    """Compute SHA1 hash of a file."""
    h = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def guess_file_type(filename: str) -> str:
    """Guess file type from extension."""
    ext = os.path.splitext(filename)[1].lower()
    type_map = {
        '.bin': 'Binary flight log',
        '.tlog': 'MAVLink telemetry log',
        '.log': 'Flight log text',
        '.dat': 'Flight data',
        '.csv': 'CSV data',
        '.mp4': 'MP4 video',
        '.jpg': 'JPEG image',
        '.jpeg': 'JPEG image',
        '.png': 'PNG image',
        '.xml': 'XML document',
        '.cfg': 'Configuration',
        '.param': 'Parameters',
    }
    return type_map.get(ext, 'Unknown')


def build_file_tree(base_dir: str | Path, max_depth: int = 10) -> dict[str, Any]:
    """Build a nested JSON tree of the extracted filesystem.

    Returns:
        {
            "name": "basename",
            "type": "directory",
            "size": total_bytes,
            "children": [
                {"name": "file.txt", "type": "file", "size": 1234, "sha1": "abc..."},
                {"name": "subdir", "type": "directory", "size": ..., "children": [...]},
            ]
        }
    """
    base_dir = Path(base_dir)
    if not base_dir.is_dir():
        return {"name": str(base_dir), "type": "directory", "size": 0, "children": []}

    def _build(path: Path, depth: int) -> dict:
        if depth > max_depth:
            return {"name": path.name, "type": "directory", "size": 0, "children": []}

        children = []
        total_size = 0
        try:
            entries = sorted(path.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            entries = []

        for entry in entries:
            if entry.name.startswith('.'):
                continue
            if entry.is_dir():
                sub = _build(entry, depth + 1)
                children.append(sub)
                total_size += sub.get("size", 0)
            elif entry.is_file():
                sz = entry.stat().st_size
                total_size += sz
                children.append({
                    "name": entry.name,
                    "type": "file",
                    "size": sz,
                    "sha1": compute_sha1(entry),
                    "file_type": guess_file_type(entry.name),
                })

        return {
            "name": path.name,
            "type": "directory",
            "size": total_size,
            "children": children,
        } if children else {
            "name": path.name,
            "type": "directory",
            "size": 0,
            "children": [],
        }

    return _build(base_dir, 0)


def list_all_files(base_dir: str | Path) -> list[dict[str, Any]]:
    """Return a flat list of all files with metadata."""
    base_dir = Path(base_dir)
    if not base_dir.is_dir():
        return []

    files = []
    for root, _dirs, filenames in os.walk(base_dir):
        for fname in filenames:
            if fname.startswith('.'):
                continue
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(base_dir))
            files.append({
                "path": rel,
                "size": fpath.stat().st_size,
                "sha1": compute_sha1(fpath),
                "file_type": guess_file_type(fname),
            })

    return sorted(files, key=lambda f: f["path"])


def create_download_zip(base_dir: str | Path) -> BytesIO:
    """Create an in-memory zip of the entire extracted directory."""
    base_dir = Path(base_dir)
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for file_info in list_all_files(base_dir):
            fpath = base_dir / file_info["path"]
            z.write(fpath, file_info["path"])
    buf.seek(0)
    return buf


def get_extraction_stats(base_dir: str | Path) -> dict[str, Any]:
    """Return summary stats for the extracted filesystem."""
    base_dir = Path(base_dir)
    if not base_dir.is_dir():
        return {"total_files": 0, "total_size": 0, "directories": 0}

    total_files = 0
    total_size = 0
    dirs = 0

    for root, dirnames, filenames in os.walk(base_dir):
        dirs += len(dirnames)
        for f in filenames:
            if f.startswith('.'):
                continue
            total_files += 1
            total_size += (Path(root) / f).stat().st_size

    return {
        "total_files": total_files,
        "total_size": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 1),
        "directories": dirs,
    }
