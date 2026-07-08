#!/usr/bin/env python3
"""
forensic_extract_windows.py — Native Windows Forensic Pipeline (v2.0)

A pure-Python forensic extraction pipeline using pytsk3 (The Sleuth Kit
bindings). No bash, no WSL, no Linux tools required.

Capabilities:
  - RAW (.dd, .img, .raw) direct; E01 via built-in pytsk3 or ewfexport
  - MBR/GPT partition detection
  - FAT32/NTFS/ext4/HFS+ filesystem parsing
  - Deleted/orphan file recovery
  - Parallel file extraction (ThreadPoolExecutor)
  - SHA1 hashing, file type identification, mtime preservation
  - tkinter GUI with real-time log + progress bar

Windows Setup:
    pip install pytsk3
    python forensic_extract_windows.py

For E01 images (optional):
    Download ewf-tools from https://github.com/libyal/libewf/releases
    and add ewfexport.exe to your PATH. Or convert E01 to RAW with
    FTK Imager (File → Export Disk Image → Raw format).
"""

import os
import sys
import time
import json
import hashlib
import struct
import threading
import concurrent.futures
import queue
import shutil
from datetime import datetime, timezone
from pathlib import Path

# ─── Tkinter ────────────────────────────────────────────────────────────────
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# ─── TSK / EWF ──────────────────────────────────────────────────────────────
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False


# =============================================================================
# FORENSIC ENGINE
# =============================================================================

class ForensicError(Exception):
    """Base exception for forensic pipeline errors."""
    pass


class ImageOpenError(ForensicError):
    """Failed to open disk image."""
    pass


class PartitionNotFoundError(ForensicError):
    """No valid partition found in image."""
    pass


class FilesystemOpenError(ForensicError):
    """Failed to open filesystem on partition."""
    pass


# ---------------------------------------------------------------------------
# EWF helper — find ewfexport on PATH or common install locations
# ---------------------------------------------------------------------------

def _find_ewfexport():
    """Locate ewfexport.exe in PATH or common install directories."""
    # Add tools directory to PATH search
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _tools_ewf = os.path.join(_script_dir, "tools", "ewf-tools")
    if os.path.isdir(_tools_ewf) and _tools_ewf not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _tools_ewf + os.pathsep + os.environ.get("PATH", "")

    # Check PATH first
    for dir_ in os.environ.get("PATH", "").split(os.pathsep):
        exe = os.path.join(dir_, "ewfexport.exe")
        if os.path.isfile(exe):
            return exe
        exe = os.path.join(dir_, "ewfexport")
        if os.path.isfile(exe):
            return exe
    # Common install locations
    candidates = [
        _tools_ewf + r"\ewfexport.exe",
        r"C:\Program Files\ewf-tools\bin\ewfexport.exe",
        r"C:\Program Files (x86)\ewf-tools\bin\ewfexport.exe",
        r"C:\Tools\ewf-tools\ewfexport.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _ewf_to_raw_pipe(e01_path, raw_out_path, progress_cb=None):
    """Convert E01 to raw using ewfexport subprocess.

    Returns True on success, False on failure.
    """
    ewfexport = _find_ewfexport()
    if not ewfexport:
        return False

    TIMEOUT = 7200
    try:
        proc = subprocess.Popen(
            [ewfexport, "-u", "-f", "raw",
             "-t", raw_out_path.replace('.raw', ''), e01_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            universal_newlines=True
        )
        try:
            stdout, stderr = proc.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise IOError(
                f"ewfexport timed out after {TIMEOUT}s — process blocked or "
                "storage too slow. Pre-convert to raw before uploading."
            )
        if proc.returncode != 0:
            raise IOError(f"ewfexport failed (exit {proc.returncode}): {stderr[:400]}")

        # ewfexport creates <base>.raw — verify it exists
        if not os.path.isfile(raw_out_path):
            # Check for alternative naming
            base = os.path.splitext(raw_out_path)[0]
            for f in os.listdir(os.path.dirname(raw_out_path)):
                if f.startswith(os.path.basename(base)) and f.endswith('.raw'):
                    os.rename(os.path.join(os.path.dirname(raw_out_path), f),
                              raw_out_path)
                    break
        return os.path.isfile(raw_out_path)
    except Exception as e:
        raise ImageOpenError(f"ewfexport conversion failed: {e}")


# ---------------------------------------------------------------------------
# Image opener — handles RAW and E01 on Windows
# ---------------------------------------------------------------------------

def open_image(image_path):
    """Open a disk image — returns (img_info, format_label).

    For RAW images: uses pytsk3.Img_Info directly.
    For E01 images:
      1. Tries pytsk3.Img_Info(path) directly (works if libtsk has EWF support)
      2. Falls back to looking for ewfexport.exe to convert E01 → temp RAW
      3. As last resort, raises ImageOpenError with conversion instructions

    Returns (pytsk3.Img_Info, format_string).
    """
    image_path = str(image_path)
    if not os.path.isfile(image_path):
        raise ImageOpenError(f"File not found: {image_path}")
    if not TSK_AVAILABLE:
        raise ImageOpenError("pytsk3 is required. Install: pip install pytsk3")

    ext = os.path.splitext(image_path)[1].lower()
    is_e01 = ext in ('.e01',)

    # ── Step 1: Try pytsk3 directly (handles E01 if libtsk has EWF support) ─
    try:
        img_info = pytsk3.Img_Info(image_path)
        return img_info, "E01 (built-in)" if is_e01 else "RAW"
    except Exception as e:
        if not is_e01:
            raise ImageOpenError(f"Failed to open RAW image: {e}")
        # E01 failed with pytsk3 — proceed to fallbacks
        first_error = e

    # ── Step 2: E01 — try ewfexport subprocess ─────────────────────────────
    if is_e01:
        import subprocess
        import tempfile

        ewfexport = _find_ewfexport()
        if ewfexport:
            temp_dir = tempfile.mkdtemp()
            temp_raw = os.path.join(temp_dir, "converted.raw")
            try:
                subprocess.run(
                    [ewfexport, "-u", "-f", "raw",
                     "-t", os.path.join(temp_dir, "converted"),
                     image_path],
                    capture_output=True, text=True,
                    stdin=subprocess.DEVNULL,
                    timeout=7200, check=True
                )
                # ewfexport produces converted.raw
                if not os.path.isfile(temp_raw):
                    temp_raw = os.path.join(temp_dir, "converted.raw")
                img_info = pytsk3.Img_Info(temp_raw)
                return img_info, "E01 → RAW (ewfexport)"
            except Exception:
                # Clean up failed temp file
                try:
                    os.remove(temp_raw)
                    os.rmdir(temp_dir)
                except Exception:
                    pass
                # Continue to step 3

        # ── Step 3: E01 — instruct user to convert manually ────────────────
        raise ImageOpenError(
            "Cannot open E01 image. Two options:\n\n"
            "1. Install ewf-tools for Windows:\n"
            "   Download from: https://github.com/libyal/libewf/releases\n"
            "   Then run:  ewfexport image.E01 -t output -f raw\n\n"
            "2. Use FTK Imager to convert E01 to RAW (.dd):\n"
            "   File → Export Disk Image → Raw format\n\n"
            f"Technical details: {first_error}"
        )

    raise ImageOpenError(f"Unexpected error opening image: {e}")


# ---------------------------------------------------------------------------
# Partition detection
# ---------------------------------------------------------------------------

def detect_best_partition(img_info):
    """Return (offset_bytes, sector_size, part_desc) for the best partition.

    Iterates over the volume system, selects the largest non-metadata
    partition. Returns 0 offset if no partition table is found.
    """
    try:
        volume_info = pytsk3.Volume_Info(img_info)
    except Exception:
        # No partition table — treat whole image as one partition
        return 0, 512, "superfloppy (no partition table)"

    best = None
    best_len = 0

    for part in volume_info:
        desc = part.desc.decode('utf-8', errors='replace').strip()
        flags = part.flags

        # Skip metadata / unallocated / empty
        lower_desc = desc.lower()
        if any(kw in lower_desc for kw in ['unalloc', 'meta', 'extended', 'empty', 'primary table']):
            continue
        if flags & pytsk3.TSK_VS_PART_FLAG_UNALLOC:
            continue

        part_len = part.len
        if part_len > best_len:
            best_len = part_len
            best = part

    if best is None:
        return 0, 512, "superfloppy (no valid partitions found)"

    offset_bytes = best.start * best.sector_size if hasattr(best, 'sector_size') else best.start * 512
    sector_size = getattr(best, 'sector_size', 512)
    desc = best.desc.decode('utf-8', errors='replace').strip()
    return offset_bytes, sector_size, desc


# ---------------------------------------------------------------------------
# Filesystem navigation
# ---------------------------------------------------------------------------

FS_TYPE_MAP = {
    0x01: "FAT12",
    0x04: "FAT16",
    0x06: "FAT16B",
    0x07: "NTFS",
    0x0B: "FAT32",
    0x0C: "FAT32X",
    0x0E: "FAT16X",
    0x0F: "Extended",
    0x83: "Linux EXT",
    0xAF: "HFS+",
}


def open_filesystem(img_info, offset_bytes):
    """Open filesystem at the given byte offset.

    Returns (fs_info, fs_type_str, fs_label).
    """
    try:
        fs_info = pytsk3.FS_Info(img_info, offset=offset_bytes)
    except Exception as e:
        raise FilesystemOpenError(f"Failed to open filesystem: {e}")

    # Determine type
    fs_type = "unknown"
    fs_label = ""
    try:
        fs_info_str = str(fs_info.info)  # Uses pytsk3's repr
        if 'NTFS' in fs_info_str:
            fs_type = "NTFS"
        elif 'FAT12' in fs_info_str or 'FAT16' in fs_info_str or 'FAT32' in fs_info_str:
            fs_type = "FAT"
        elif 'Ext4' in fs_info_str or 'Ext3' in fs_info_str or 'Ext2' in fs_info_str:
            fs_type = "EXT"
        elif 'HFS' in fs_info_str:
            fs_type = "HFS"
        elif 'exFAT' in fs_info_str:
            fs_type = "exFAT"
    except Exception:
        pass

    try:
        fs_label = fs_info.info.vol_name.decode('utf-8', errors='replace').strip()
    except Exception:
        fs_label = ""

    return fs_info, fs_type, fs_label


# ---------------------------------------------------------------------------
# File entry wrapper
# ---------------------------------------------------------------------------

class FileEntry:
    """Normalised file entry from TSK directory traversal."""

    __slots__ = (
        'inode', 'name', 'path', 'size', 'mtime', 'atime', 'ctime', 'crtime',
        'is_dir', 'is_deleted', 'is_orphan', 'type_str', 'tsk_entry',
    )

    def __init__(self, tsk_entry, full_path):
        self.tsk_entry = tsk_entry
        meta = tsk_entry.info.meta
        name_info = tsk_entry.info.name

        self.inode = meta.addr if meta else 0
        self.name = name_info.name.decode('utf-8', errors='replace')

        # Normalize path: remove leading /
        self.path = full_path.lstrip('/')

        self.size = meta.size if meta else 0
        self.mtime = meta.mtime if meta else 0
        self.atime = meta.atime if meta else 0
        self.ctime = meta.ctime if meta else 0
        self.crtime = meta.crtime if meta else 0

        # Type detection
        name_type = name_info.type
        self.is_dir = (name_type == pytsk3.TSK_FS_NAME_TYPE_DIR)
        self.is_orphan = (name_type == pytsk3.TSK_FS_NAME_TYPE_ORPHAN)

        # Deleted / unallocated detection
        if meta and meta.flags:
            self.is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
        else:
            self.is_deleted = True  # No metadata = unallocated

        # Type string for logging
        if self.is_dir:
            self.type_str = "d/d"
        elif self.is_orphan:
            self.type_str = "o/o"
        elif self.is_deleted:
            self.type_str = "r/r *"  # deleted marker
        else:
            self.type_str = "r/r"


# ---------------------------------------------------------------------------
# Recursive filesystem walker
# ---------------------------------------------------------------------------

def walk_filesystem(fs_info, root_path="/", max_depth=999, progress_callback=None):
    """Recursively enumerate all entries in the filesystem.

    Yields FileEntry objects for every file (not directories).
    Directories are skipped but their paths ensure parent dirs exist.
    """
    def _walk(path, depth):
        if depth > max_depth:
            return
        try:
            directory = fs_info.open_dir(path)
        except IOError:
            return  # Permission denied / corrupt directory

        for entry in directory:
            name_info = entry.info.name
            if not name_info:
                continue

            name = name_info.name.decode('utf-8', errors='replace')

            # Skip . and ..
            if name in ('.', '..'):
                continue

            # Build full path
            if path == "/":
                full_path = f"/{name}"
            else:
                full_path = f"{path}/{name}"

            try:
                fe = FileEntry(entry, full_path)
            except Exception:
                continue  # Skip corrupt entries

            if progress_callback:
                progress_callback(fe)

            if fe.is_dir:
                # Recurse into directory
                yield from _walk(full_path, depth + 1)
            else:
                # Yield regular file (including deleted/orphan)
                yield fe

    yield from _walk(root_path, 0)


# ---------------------------------------------------------------------------
# Extraction engine
# ---------------------------------------------------------------------------

def extract_file(fs_info, entry, output_dir, timestamp=True, compute_hash=False, compute_filetype=False):
    """Extract a single file entry to the output directory.

    Args:
        fs_info: pytsk3.FS_Info object
        entry: FileEntry object
        output_dir: Root output path
        timestamp: Restore mtime if True
        compute_hash: Compute SHA1 if True
        compute_filetype: Run file type detection if True

    Returns:
        dict with keys: inode, path, status, sha1, filetype, size, error
    """
    result = {
        'inode': entry.inode,
        'path': entry.path,
        'status': 'FAILED',
        'sha1': '',
        'filetype': '',
        'size': 0,
        'error': '',
    }

    # Determine output path
    safe_path = entry.path.replace('..', '_').replace('\x00', '_')
    while '//' in safe_path:
        safe_path = safe_path.replace('//', '/')

    if entry.is_orphan:
        out_path = os.path.join(output_dir, '$OrphanFiles',
                                f"{entry.inode}_{os.path.basename(safe_path)}")
    elif entry.is_deleted:
        out_path = os.path.join(output_dir, '$Deleted', safe_path)
    else:
        out_path = os.path.join(output_dir, 'fs', safe_path)

    # Create parent directory
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    try:
        # Read file via TSK
        tsk_file = fs_info.open_meta(entry.inode)
        file_size = tsk_file.info.meta.size if tsk_file.info.meta else 0

        if file_size == 0:
            # Zero-byte file: create empty
            open(out_path, 'wb').close()
        else:
            # Read in chunks to avoid OOM on huge files
            hasher = hashlib.sha1() if compute_hash else None
            with open(out_path, 'wb') as f:
                offset = 0
                chunk_size = 4 * 1024 * 1024  # 4 MB chunks
                while offset < file_size:
                    to_read = min(chunk_size, file_size - offset)
                    data = tsk_file.read_random(offset, to_read)
                    if not data:
                        break
                    f.write(data)
                    if hasher:
                        hasher.update(data)
                    offset += len(data)

            if hasher:
                result['sha1'] = hasher.hexdigest()

            # File type detection (using magic bytes / extension)
            if compute_filetype:
                result['filetype'] = _detect_filetype(out_path, entry.name)

            # Restore mtime
            if timestamp and entry.mtime:
                mtime_dt = datetime.fromtimestamp(entry.mtime, tz=timezone.utc)
                mod_time = mtime_dt.timestamp()
                os.utime(out_path, (mod_time, mod_time))

        result['status'] = 'OK'
        result['size'] = file_size

    except IOError as e:
        result['error'] = f"IO_ERROR: {e}"
        # Remove partial file
        if os.path.isfile(out_path) and os.path.getsize(out_path) == 0:
            try:
                os.remove(out_path)
            except Exception:
                pass
    except Exception as e:
        result['error'] = f"EXCEPTION: {e}"
        if os.path.isfile(out_path) and os.path.getsize(out_path) == 0:
            try:
                os.remove(out_path)
            except Exception:
                pass

    return result


def _detect_filetype(filepath, filename):
    """Simple file type detection using extension and magic bytes."""
    # Extension-based first
    ext = os.path.splitext(filename)[1].lower()
    ext_map = {
        '.jpg': 'JPEG image', '.jpeg': 'JPEG image',
        '.png': 'PNG image', '.gif': 'GIF image',
        '.pdf': 'PDF document', '.doc': 'MS Word',
        '.docx': 'MS Word', '.xls': 'MS Excel',
        '.xlsx': 'MS Excel', '.zip': 'ZIP archive',
        '.rar': 'RAR archive', '.7z': '7z archive',
        '.tar': 'TAR archive', '.gz': 'GZip archive',
        '.avi': 'AVI video', '.mp4': 'MP4 video',
        '.mp3': 'MP3 audio', '.wav': 'WAV audio',
        '.txt': 'Text file', '.html': 'HTML document',
        '.xml': 'XML document', '.exe': 'PE executable',
        '.dll': 'PE DLL',
    }
    if ext in ext_map:
        return ext_map[ext]

    # Magic bytes
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
        if header[:4] == b'\x89PNG':
            return 'PNG image'
        if header[:2] == b'\xff\xd8':
            return 'JPEG image'
        if header[:4] == b'%PDF':
            return 'PDF document'
        if header[:2] == b'PK':
            return 'ZIP/DOCX/XLSX archive'
        if header[:2] == b'MZ':
            return 'PE executable'
        if header[:4] == b'\x1a\x45\xdf\xa3':
            return 'WebM/MKV video'
        if header[:4] == b'ftyp':
            return 'MP4 video'
        if header[:4] == b'RIFF':
            return 'AVI/WAV'
        if b'<?xml' in header or b'<html' in header.lower():
            return 'XML/HTML document'
    except Exception:
        pass

    return 'unknown'


# =============================================================================
# MAIN PIPELINE
# =============================================================================

class ForensicPipeline:
    """Orchestrates the full forensic extraction pipeline.

    Provides callback hooks for GUI integration.
    """

    def __init__(self, image_path, output_dir, offset=None, max_jobs=4,
                 icat_timeout=30, compute_hash=True, compute_filetype=True,
                 resume=False, dry_run=False):
        self.image_path = str(image_path)
        self.output_dir = str(output_dir)
        self.user_offset = offset
        self.max_jobs = max_jobs
        self.icat_timeout = icat_timeout
        self.compute_hash = compute_hash
        self.compute_filetype = compute_filetype
        self.resume = resume
        self.dry_run = dry_run

        # State
        self.log_dir = ""
        self.img_info = None
        self.fs_info = None
        self.partition_offset = 0
        self.partition_desc = ""
        self.fs_type = ""
        self.fs_label = ""
        self.cancelled = False

        # Stats
        self.stats = {
            'allocated': 0,
            'deleted': 0,
            'orphan': 0,
            'extracted': 0,
            'failed': 0,
            'skipped': 0,
            'total_bytes': 0,
        }

        # Callbacks
        self.on_log = None       # func(level, message)
        self.on_progress = None  # func(current, total, label)
        self.on_file_done = None # func(result_dict)
        self.on_stage = None     # func(stage_name)

        # Resume checkpoint set
        self.checkpoint = set()
        if resume:
            self._load_checkpoint()

    def _load_checkpoint(self):
        """Load previously extracted inodes from checkpoint file."""
        cp_path = os.path.join(self.output_dir, 'logs', 'checkpoint_ok.txt')
        if os.path.isfile(cp_path):
            try:
                with open(cp_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self.checkpoint.add(line)
                self._log('info', f"Loaded {len(self.checkpoint)} checkpoint entries")
            except Exception as e:
                self._log('warn', f"Could not load checkpoint file: {e}")

    def _save_checkpoint(self, inode):
        """Append extracted inode to checkpoint file."""
        cp_path = os.path.join(self.output_dir, 'logs', 'checkpoint_ok.txt')
        try:
            with open(cp_path, 'a') as f:
                f.write(f"{inode}\n")
        except Exception:
            pass

    def _log(self, level, message):
        if self.on_log:
            self.on_log(level, message)

    def _stage(self, name):
        if self.on_stage:
            self.on_stage(name)
        self._log('stage', f"  {name}")
        self._log('info', f"{'=' * 50}")
        self._log('info', f"  {name}")
        self._log('info', f"{'=' * 50}")

    # -----------------------------------------------------------------------
    # Pipeline execution
    # -----------------------------------------------------------------------

    def run(self):
        """Execute the full extraction pipeline.

        Returns dict with summary stats.
        """
        start_time = time.time()

        # ── Stage 0: Setup ───────────────────────────────────────────────
        self.log_dir = os.path.join(self.output_dir, 'logs')
        os.makedirs(os.path.join(self.output_dir, 'fs'), exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

        self._log('info', f"Image : {self.image_path}")
        self._log('info', f"Output: {self.output_dir}")
        self._log('info', f"Jobs  : {self.max_jobs}")
        self._log('info', f"Hash  : {self.compute_hash}")
        self._log('info', f"Filetype: {self.compute_filetype}")
        self._log('info', f"Resume: {self.resume}")
        self._log('info', f"Dry run: {self.dry_run}")
        self._log('info', "")

        # ── Stage 1: Image handling ───────────────────────────────────────
        self._stage("Stage 1: Image Handling")
        if not TSK_AVAILABLE:
            raise ForensicError("pytsk3 is required. Install: pip install pytsk3")

        self.img_info, is_e01 = open_image(self.image_path)
        img_size = self.img_info.get_size()
        self._log('info', f"Image size: {img_size / (1024**3):.1f} GB")
        self._log('info', f"Format: {'E01 (pyewf)' if is_e01 else 'RAW (pytsk3)'}")

        # ── Stage 2: Partition detection ─────────────────────────────────
        self._stage("Stage 2: Partition Detection")
        if self.user_offset is not None:
            self.partition_offset = self.user_offset
            self.partition_desc = "user-specified"
            self._log('info', f"Using user-specified offset: {self.partition_offset}")
        else:
            offset, sec_size, desc = detect_best_partition(self.img_info)
            self.partition_offset = offset
            self.partition_desc = desc
            self._log('info', f"Selected partition: offset={offset} bytes, desc={desc}")

        self._log('info', f"Partition byte offset: {self.partition_offset}")

        # ── Stage 3: Filesystem identification ───────────────────────────
        self._stage("Stage 3: Filesystem Identification")
        self.fs_info, self.fs_type, self.fs_label = open_filesystem(
            self.img_info, self.partition_offset
        )
        self._log('info', f"Filesystem type : {self.fs_type}")
        self._log('info', f"Volume label    : {self.fs_label}")

        # ── Stage 4-5: Enumerate + parse ─────────────────────────────────
        self._stage("Stage 4-5: Filesystem Enumeration")

        all_files = []
        total_count = [0]

        def _progress(fe):
            total_count[0] += 1
            if total_count[0] % 1000 == 0:
                self._log('info', f"  Enumerated {total_count[0]} entries...")
            if fe.is_dir:
                return
            if fe.is_deleted and not fe.is_orphan:
                self.stats['deleted'] += 1
            elif fe.is_orphan:
                self.stats['orphan'] += 1
                self.stats['deleted'] += 1
            else:
                self.stats['allocated'] += 1
            all_files.append(fe)

        for fe in walk_filesystem(self.fs_info, progress_callback=_progress):
            pass  # Callback handles everything

        self._log('info', f"Total files: {len(all_files)} "
                         f"(alloc={self.stats['allocated']}, "
                         f"deleted={self.stats['deleted']}, "
                         f"orphan={self.stats['orphan']})")

        if self.dry_run:
            self._log('info', "DRY RUN — no files written")
            elapsed = time.time() - start_time
            return {**self.stats, 'elapsed': elapsed, 'files': all_files}

        # ── Stage 6: Directory tree reconstruction ───────────────────────
        self._stage("Stage 6: Directory Tree Reconstruction")
        dirs_created = 0
        for fe in all_files:
            parent = os.path.dirname(
                os.path.join(self.output_dir, 'fs', fe.path)
            )
            if not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
                dirs_created += 1

        os.makedirs(os.path.join(self.output_dir, 'fs', '$Deleted'), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, 'fs', '$OrphanFiles'), exist_ok=True)
        self._log('info', f"Created {dirs_created} directories")

        # ── Stage 7-8: File extraction ───────────────────────────────────
        self._stage("Stage 7-8: File Extraction")

        # Order: allocated first, then deleted, then orphan
        order_map = {'alloc': 0, 'deleted': 1, 'orphan': 2}
        all_files.sort(key=lambda fe: (
            order_map.get('orphan' if fe.is_orphan else 'deleted' if fe.is_deleted else 'alloc', 0),
            fe.inode
        ))

        # Filter checkpoint (resume)
        if self.resume and self.checkpoint:
            before = len(all_files)
            all_files = [fe for fe in all_files if str(fe.inode) not in self.checkpoint]
            self.stats['skipped'] = before - len(all_files)
            self._log('info', f"Resume: skipping {self.stats['skipped']} already-extracted files")

        total = len(all_files)
        self._log('info', f"Extracting {total} files ({self.max_jobs} workers)...")

        # Write CSV headers
        extracted_csv = os.path.join(self.log_dir, 'extracted.tsv')
        failed_csv = os.path.join(self.log_dir, 'failed.tsv')
        with open(extracted_csv, 'w', encoding='utf-8') as f:
            f.write("inode\tpath\tsha1\tfiletype\tstatus\tsize\n")
        with open(failed_csv, 'w', encoding='utf-8') as f:
            f.write("inode\tpath\terror\n")

        # Parallel extraction
        done_count = [0]
        lock = threading.Lock()

        def _extract_worker(fe):
            if self.cancelled:
                return
            result = extract_file(
                self.fs_info, fe, self.output_dir,
                timestamp=True,
                compute_hash=self.compute_hash,
                compute_filetype=self.compute_filetype,
            )
            with lock:
                done_count[0] += 1
                if done_count[0] % 100 == 0 or done_count[0] == total:
                    pct = done_count[0] * 100 // total if total else 0
                    self._log('info', f"  [{done_count[0]}/{total}] {pct}%")
                if self.on_progress:
                    self.on_progress(done_count[0], total, fe.path)

                # Write to CSV
                if result['status'] == 'OK':
                    self.stats['extracted'] += 1
                    self.stats['total_bytes'] += result['size']
                    if self.resume:
                        self._save_checkpoint(fe.inode)
                    with open(extracted_csv, 'a', encoding='utf-8') as f:
                        f.write(f"{fe.inode}\t{fe.path}\t{result['sha1']}\t"
                                f"{result['filetype']}\tOK\t{result['size']}\n")
                else:
                    self.stats['failed'] += 1
                    with open(failed_csv, 'a', encoding='utf-8') as f:
                        f.write(f"{fe.inode}\t{fe.path}\t{result['error']}\n")

                if self.on_file_done:
                    self.on_file_done(result)

        # Thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_jobs) as executor:
            futures = {executor.submit(_extract_worker, fe): fe for fe in all_files}
            try:
                for future in concurrent.futures.as_completed(futures):
                    if self.cancelled:
                        # Cancel remaining
                        for f in futures:
                            f.cancel()
                        break
                    future.result()  # Propagate exceptions
            except KeyboardInterrupt:
                self.cancelled = True
                for f in futures:
                    f.cancel()

        elapsed = time.time() - start_time

        # ── Stage 9: Report ──────────────────────────────────────────────
        self._stage("Stage 9: Summary Report")
        report = self._generate_report(elapsed)
        self._log('info', f"Pipeline finished in {elapsed:.1f}s")

        return {
            **self.stats,
            'elapsed': elapsed,
            'fs_type': self.fs_type,
            'partition_offset': self.partition_offset,
            'report': report,
        }

    # -----------------------------------------------------------------------
    # Report generation
    # -----------------------------------------------------------------------

    def _generate_report(self, elapsed):
        """Write summary report to log directory and return as string."""
        report_path = os.path.join(self.log_dir, 'summary.txt')

        lines = [
            "═" * 60,
            "   FORENSIC EXTRACTION PIPELINE — WINDOWS NATIVE",
            "═" * 60,
            f"Image            : {self.image_path}",
            f"Output           : {self.output_dir}",
            f"Partition Offset : {self.partition_offset} bytes",
            f"Filesystem       : {self.fs_type} ({self.fs_label})",
            f"Completed        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Elapsed          : {elapsed:.1f} seconds",
            "",
            "─── EXTRACTION STATISTICS ──────────────────────────────",
            f"Files Enumerated (allocated)  : {self.stats['allocated']}",
            f"Files Enumerated (deleted)    : {self.stats['deleted']}",
            f"Files Enumerated (orphan)     : {self.stats['orphan']}",
            f"Extracted Successfully        : {self.stats['extracted']}",
            f"Failed Extractions            : {self.stats['failed']}",
            f"Skipped (resume)              : {self.stats['skipped']}",
            f"Total Bytes Extracted         : {self.stats['total_bytes'] / (1024**2):.1f} MB",
            "",
            "─── OUTPUT ────────────────────────────────────────────",
            f"  {os.path.join(self.output_dir, 'fs')}",
            f"  {os.path.join(self.output_dir, 'logs')}",
            "",
            "─── LOG FILES ─────────────────────────────────────────",
            f"  {os.path.join(self.log_dir, 'extracted.tsv')}",
            f"  {os.path.join(self.log_dir, 'failed.tsv')}",
            f"  {os.path.join(self.log_dir, 'summary.txt')}",
            "",
        ]

        report = "\n".join(lines)
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report + "\n")
        except Exception:
            pass

        return report


# =============================================================================
# TKINTER GUI
# =============================================================================

class ForensicGUI:
    """tkinter GUI wrapping ForensicPipeline."""

    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Extraction Pipeline — Windows Native")
        self.root.geometry("960x800")
        self.root.minsize(700, 600)

        # State
        self.pipeline = None
        self.running = False
        self.cancelled = False
        self._thread = None

        # Style
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        self._build_ui()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var,
                               relief=tk.SUNKEN, anchor=tk.W, padding=(4, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initial checks
        self.root.after(200, self._initial_checks)

    # -------------------------------------------------------------------
    # UI Build
    # -------------------------------------------------------------------

    def _build_ui(self):
        # Menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Output Directory", command=self._open_output)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        # Main paned window
        self.pw = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.pw.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # ── Top: Configuration ──
        top = ttk.Frame(self.pw)
        self.pw.add(top, weight=0)

        # Input / Output
        io = ttk.LabelFrame(top, text=" Input / Output ", padding=8)
        io.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(io, text="Image path:", width=12, anchor=tk.E).grid(row=0, column=0, sticky=tk.E, padx=(0, 4))
        self.img_var = tk.StringVar()
        ttk.Entry(io, textvariable=self.img_var).grid(row=0, column=1, sticky=tk.EW, padx=(0, 4))
        ttk.Button(io, text="Browse", command=self._browse_image).grid(row=0, column=2)

        ttk.Label(io, text="Output dir:", width=12, anchor=tk.E).grid(row=1, column=0, sticky=tk.E, padx=(0, 4))
        self.out_var = tk.StringVar()
        ttk.Entry(io, textvariable=self.out_var).grid(row=1, column=1, sticky=tk.EW, padx=(0, 4))
        ttk.Button(io, text="Browse", command=self._browse_output).grid(row=1, column=2)
        io.columnconfigure(1, weight=1)

        # Options
        opt = ttk.LabelFrame(top, text=" Options ", padding=8)
        opt.pack(fill=tk.X)

        ttk.Label(opt, text="Partition offset:").grid(row=0, column=0, sticky=tk.W, padx=4)
        self.offset_var = tk.StringVar()
        ttk.Entry(opt, textvariable=self.offset_var, width=14).grid(row=0, column=1, sticky=tk.W)

        ttk.Label(opt, text="FS type:").grid(row=0, column=2, sticky=tk.W, padx=(12, 4))
        self.fs_var = tk.StringVar(value="auto")
        cb = ttk.Combobox(opt, textvariable=self.fs_var, width=10,
                          values=["auto", "ntfs", "fat", "ext", "hfs", "exfat"])
        cb.state(["readonly"])
        cb.grid(row=0, column=3, sticky=tk.W)

        ttk.Label(opt, text="Parallel jobs:").grid(row=0, column=4, sticky=tk.W, padx=(12, 4))
        self.jobs_var = tk.IntVar(value=4)
        ttk.Spinbox(opt, from_=1, to=32, textvariable=self.jobs_var, width=5).grid(row=0, column=5, sticky=tk.W)

        self.hash_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="SHA1 hash", variable=self.hash_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=4)
        self.ft_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="File type", variable=self.ft_var).grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=4)
        self.resume_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Resume", variable=self.resume_var).grid(row=1, column=4, columnspan=2, sticky=tk.W, padx=4)

        # Buttons
        btn = ttk.Frame(top)
        btn.pack(fill=tk.X, pady=(6, 0))
        self.run_btn = ttk.Button(btn, text="▶ Start Extraction", command=self._start)
        self.run_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.cancel_btn = ttk.Button(btn, text="■ Cancel", command=self._cancel, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT)
        ttk.Button(btn, text="Clear Log", command=self._clear_log).pack(side=tk.RIGHT)

        # ── Bottom: Output ──
        log_frame = ttk.LabelFrame(self.pw, text=" Pipeline Output ", padding=4)
        self.pw.add(log_frame, weight=1)

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, state=tk.DISABLED,
                                font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        self.log_text.tag_configure("info", foreground="#6a9955")
        self.log_text.tag_configure("warn", foreground="#dcdcaa")
        self.log_text.tag_configure("error", foreground="#f44747")
        self.log_text.tag_configure("stage", foreground="#c586c0", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("header", foreground="#4fc1ff", font=("Consolas", 10, "bold"))

        vsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(log_frame, mode='determinate',
                                             variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X, pady=(4, 0))

    # -------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------

    def log(self, message, tag=None):
        def _append():
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, message + "\n", tag or ())
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)
        self.root.after(0, _append)

    def set_status(self, text):
        self.root.after(0, lambda: self.status_var.set(text))

    def _clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)

    # -------------------------------------------------------------------
    # Dialogs
    # -------------------------------------------------------------------

    def _browse_image(self):
        path = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[("Disk images", "*.dd *.img *.raw *.E01 *.e01 *.bin"),
                       ("All files", "*.*")])
        if path:
            self.img_var.set(path)
            if not self.out_var.get():
                base = os.path.splitext(os.path.basename(path))[0]
                self.out_var.set(os.path.join(os.path.dirname(path), base + "_extracted"))

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.out_var.set(path)

    def _open_output(self):
        out = self.out_var.get()
        if out and os.path.isdir(out):
            try:
                os.startfile(out)
            except Exception:
                pass
        else:
            messagebox.showinfo("Output Directory", "Directory does not exist yet.")

    def _initial_checks(self):
        issues = []
        if not TSK_AVAILABLE:
            issues.append("pytsk3 not installed (pip install pytsk3)")
        if not _find_ewfexport():
            issues.append("ewfexport not found — E01 images will fail. Install ewf-tools or convert to RAW first.")

        if issues:
            for issue in issues:
                self.log(f"[WARN] {issue}", "warn")
            messagebox.showwarning("Missing Dependencies", "\n".join(issues))
        else:
            self.log("[INFO] All dependencies found", "info")

    # -------------------------------------------------------------------
    # Pipeline lifecycle
    # -------------------------------------------------------------------

    def _start(self):
        if self.running:
            messagebox.showwarning("Already Running", "Extraction is in progress.")
            return

        img = self.img_var.get().strip()
        out = self.out_var.get().strip()

        if not img or not os.path.isfile(img):
            messagebox.showerror("Invalid Image", "Please select a valid image file.")
            return
        if not out:
            messagebox.showerror("Missing Output", "Please select an output directory.")
            return

        self.cancelled = False
        self.running = True
        self.run_btn.configure(state=tk.DISABLED)
        self.cancel_btn.configure(state=tk.NORMAL)
        self._clear_log()
        self.progress_var.set(0)

        offset = None
        if self.offset_var.get().strip():
            try:
                offset = int(self.offset_var.get().strip())
            except ValueError:
                messagebox.showerror("Invalid Offset", "Partition offset must be an integer (bytes).")
                self.running = False
                self.run_btn.configure(state=tk.NORMAL)
                self.cancel_btn.configure(state=tk.DISABLED)
                return

        self._thread = threading.Thread(target=self._run, args=(img, out, offset), daemon=True)
        self._thread.start()

    def _run(self, img, out, offset):
        """Run pipeline in background thread."""
        self.pipeline = ForensicPipeline(
            image_path=img,
            output_dir=out,
            offset=offset,
            max_jobs=self.jobs_var.get(),
            compute_hash=self.hash_var.get(),
            compute_filetype=self.ft_var.get(),
            resume=self.resume_var.get(),
        )

        # Wire callbacks
        def log_cb(level, msg):
            tag_map = {'info': 'info', 'warn': 'warn', 'error': 'error', 'stage': 'stage'}
            self.log(f"[{level.upper()}] {msg}", tag_map.get(level))
            if 'offset' in msg.lower() or 'filesystem' in msg.lower():
                self.set_status(msg[:80])

        def progress_cb(current, total, path):
            if total > 0:
                self.progress_var.set(current * 100.0 / total)

        self.pipeline.on_log = log_cb
        self.pipeline.on_progress = progress_cb

        try:
            self.log("═" * 60, "header")
            self.log("  FORENSIC EXTRACTION PIPELINE — WINDOWS NATIVE", "header")
            self.log("═" * 60, "header")
            self.set_status("Running...")

            result = self.pipeline.run()

            if self.cancelled:
                self.log("[WARN] Cancelled by user", "warn")
                self.set_status("Cancelled")
            else:
                self.log("")
                self.log(f"[INFO] Pipeline completed in {result['elapsed']:.1f}s", "info")
                self.log(f"[INFO] Extracted: {result['extracted']}   "
                         f"Failed: {result['failed']}   "
                         f"Skipped: {result.get('skipped', 0)}", "info")
                self.set_status(f"Completed — {result['extracted']} files, "
                                f"{result.get('total_bytes', 0) / (1024**2):.0f} MB")
                self.log("")
                for line in result.get('report', '').split('\n'):
                    self.log(line)

        except Exception as e:
            self.log(f"[ERROR] Pipeline failed: {e}", "error")
            self.set_status(f"Failed: {e}")
            import traceback
            self.log(traceback.format_exc(), "error")
        finally:
            self.running = False
            self.root.after(0, lambda: self.run_btn.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.cancel_btn.configure(state=tk.DISABLED))

    def _cancel(self):
        if self.pipeline and self.running:
            self.cancelled = True
            self.pipeline.cancelled = True
            self.log("[WARN] Cancelling...", "warn")
            self.set_status("Cancelling...")

    def _on_close(self):
        if self.running:
            if not messagebox.askyesno("Confirm", "Extraction in progress. Cancel and exit?"):
                return
            self._cancel()
        self.root.destroy()


# =============================================================================
# CLI MODE
# =============================================================================

def cli_main():
    """Run pipeline from command line (no GUI)."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Windows Native Forensic Extraction Pipeline"
    )
    parser.add_argument("-i", "--image", required=True, help="Disk image path")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-p", "--offset", type=int, help="Partition byte offset")
    parser.add_argument("-j", "--jobs", type=int, default=4, help="Parallel workers")
    parser.add_argument("--no-hash", action="store_true", help="Skip SHA1")
    parser.add_argument("--no-filetype", action="store_true", help="Skip file type")
    parser.add_argument("-r", "--resume", action="store_true", help="Resume extraction")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Enumerate only")

    args = parser.parse_args()

    pipeline = ForensicPipeline(
        image_path=args.image,
        output_dir=args.output,
        offset=args.offset,
        max_jobs=args.jobs,
        compute_hash=not args.no_hash,
        compute_filetype=not args.no_filetype,
        resume=args.resume,
        dry_run=args.dry_run,
    )

    def cli_log(level, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{level.upper()}] {msg}")

    pipeline.on_log = cli_log
    result = pipeline.run()

    print("\n" + result.get('report', ''))
    return 0 if result['failed'] == 0 else 1


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    if not TSK_AVAILABLE:
        print("FATAL: pytsk3 is required.", file=sys.stderr)
        print("Install: pip install pytsk3", file=sys.stderr)
        input("Press Enter to exit...")
        sys.exit(1)

    if TKINTER_AVAILABLE and not ('--cli' in sys.argv or '-n' in sys.argv and '--dry-run' not in sys.argv):
        root = tk.Tk()
        app = ForensicGUI(root)
        root.protocol("WM_DELETE_WINDOW", app._on_close)
        root.mainloop()
    else:
        sys.exit(cli_main())


if __name__ == "__main__":
    main()
