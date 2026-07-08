"""Stage 2: Filesystem Extraction via The Sleuth Kit

Uses pytsk3 to enumerate and recover all files from the mounted image.
Builds the file manifest in the database.
"""

import os
import hashlib
from pathlib import Path

import pytsk3

from . import manifest_db


def compute_sha256(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def open_image(block_access_path):
    return pytsk3.Img_Info(block_access_path)


def detect_best_partition(img_info):
    try:
        vol_info = pytsk3.Volume_Info(img_info)
    except Exception:
        return 0, "No partition table (raw filesystem)"

    best_offset = 0
    best_desc = "raw"
    best_size = 0

    for part in vol_info:
        desc = part.desc or b""
        if b"Unallocated" in desc or b"Table" in desc:
            continue
        if part.len and part.len > best_size:
            best_offset = part.start * 512
            best_desc = f"Partition {part.addr} ({desc})"
            best_size = part.len * 512

    return best_offset, best_desc


def open_filesystem(img_info, offset):
    return pytsk3.FS_Info(img_info, offset=offset)


def walk_fs(fs_info, path):
    """Recursively walk a directory, yielding (entry, dirpath)."""
    try:
        directory = fs_info.open_dir(path)
    except Exception:
        return

    for entry in directory:
        nameobj = entry.info.name
        name = nameobj.name
        if not name or name in (b".", b".."):
            continue

        # Build full path
        p = path.rstrip("/") + "/" + name.decode("utf-8", errors="replace")

        yield entry, path

        # Recurse into directories
        meta = entry.info.meta
        if meta is not None:
            if meta.type == pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR:
                yield from walk_fs(fs_info, p)


def extract_file(fs_info, entry, output_dir):
    """Extract a regular file. Returns file_data dict or None."""
    meta = entry.info.meta
    nameobj = entry.info.name

    if meta is None or meta.size is None:
        return None
    if meta.type != pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG:
        return None

    size = meta.size
    inode = str(meta.addr)

    if size == 0:
        return None

    out_path = os.path.join(output_dir, "extracted", str(meta.addr))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    try:
        with open(out_path, "wb") as f:
            offset = 0
            remaining = size
            while remaining > 0:
                chunk_size = min(65536, remaining)
                data = entry.read_random(offset, chunk_size)
                if not data or len(data) == 0:
                    break
                f.write(data)
                offset += len(data)
                remaining -= len(data)
    except Exception:
        return None

    if os.path.getsize(out_path) == 0:
        os.remove(out_path)
        return None

    unalloc = bool(nameobj.flags & pytsk3.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_UNALLOC)

    def fmt_time(t):
        if t and t > 0:
            from datetime import datetime, timezone
            try:
                return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
            except (OSError, ValueError):
                return None
        return None

    return {
        "inode": inode,
        "path": "/" + nameobj.name.decode("utf-8", errors="replace"),
        "extracted_path": out_path,
        "size_bytes": size,
        "is_deleted": 1 if unalloc else 0,
        "mtime": fmt_time(meta.mtime),
        "atime": fmt_time(meta.atime),
        "ctime": fmt_time(meta.ctime),
        "crtime": fmt_time(meta.crtime) if hasattr(meta, "crtime") else None,
    }


def run_stage2(case_metadata, case_id, output_dir, log_cb=None):
    block_access_path = case_metadata["block_access_path"]
    skip_partition = case_metadata.get("extra", {}).get("skip_partition", False)

    def log(level, msg):
        if log_cb:
            log_cb(level, msg)
        print(f"[Stage 2] [{level}] {msg}")

    log("stage", "Opening image with pytsk3")

    try:
        img_info = open_image(block_access_path)
    except Exception as e:
        log("error", f"Cannot open image: {e}")
        raise

    img_size = img_info.get_size()
    log("info", f"Image size: {img_size / (1024**3):.1f} GB")

    if skip_partition:
        partition_offset = 0
        partition_desc = "No partition (logical/mounted filesystem)"
        log("info", "Skipping partition detection (logical image)")
    else:
        partition_offset, partition_desc = detect_best_partition(img_info)
        log("info", f"Selected partition: offset={partition_offset} bytes, {partition_desc}")

    log("stage", "Opening filesystem")
    try:
        fs_info = open_filesystem(img_info, partition_offset)
    except Exception as e:
        log("error", f"Cannot open filesystem: {e}")
        raise

    fs_type = str(fs_info.info.ftype) if hasattr(fs_info.info, "ftype") else "unknown"
    log("info", f"Filesystem type: {fs_type}")

    log("stage", "Enumerating and extracting files")

    stats = {"allocated": 0, "deleted": 0, "orphan": 0, "extracted": 0, "failed": 0}
    file_count = 0

    for entry, dirpath in walk_fs(fs_info, "/"):
        meta = entry.info.meta
        nameobj = entry.info.name
        if meta is None:
            continue

        is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR
        if is_dir:
            continue

        is_deleted = bool(nameobj.flags & pytsk3.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_UNALLOC)

        if is_deleted:
            stats["deleted"] += 1
        else:
            stats["allocated"] += 1

        file_count += 1
        if file_count % 500 == 0:
            log("info", f"  Enumerated {file_count} entries...")

        file_data = extract_file(fs_info, entry, output_dir)

        if file_data:
            stats["extracted"] += 1
            file_row = {
                "id": manifest_db.new_file_id(),
                "case_id": case_id,
                "inode": file_data["inode"],
                "path": file_data["path"],
                "extracted_path": file_data["extracted_path"],
                "size_bytes": file_data["size_bytes"],
                "is_deleted": file_data["is_deleted"],
                "mtime": file_data["mtime"],
                "atime": file_data["atime"],
                "ctime": file_data["ctime"],
                "crtime": file_data["crtime"],
                "recovery_status": "ok",
            }
            manifest_db.insert_file(file_row)

            sha = compute_sha256(file_data["extracted_path"])
            if sha:
                manifest_db.update_file_sha256(file_row["id"], sha)
        else:
            stats["failed"] += 1

    log("info", f"Extraction complete: {file_count} entries, {stats['extracted']} extracted, {stats['failed']} failed")

    manifest_db.update_case_stage(case_id, "stage2", 40)

    return stats
