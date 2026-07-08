"""
disk_image_analyzer.py
======================
Core analysis module for the Disk Image Analysis tab.

Hard requirement: pytsk3 must be installed.
  pip install pytsk3

If pytsk3 is missing, all public functions raise ImportError immediately —
no silent degradation to hand-rolled parsers.

DatCon (.DAT parsing) requires Java on PATH. Missing Java -> FlightParseError
with an explicit message; the caller records status='corrupt' + the message
in the DB row so the investigator sees it clearly.
"""

import os
import sys
import json
import csv
import math
import shutil
import hashlib
import logging
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, List, Dict, Any

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# pytsk3 -- hard require
# --------------------------------------------------------------------------
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    TSK_AVAILABLE = False


def _require_tsk():
    if not TSK_AVAILABLE:
        raise ImportError(
            "pytsk3 is not installed. Run: pip install pytsk3\n"
            "pytsk3 wraps The Sleuth Kit and is required for disk image analysis.\n"
            "If you are on Windows and pip install fails, download a prebuilt wheel from\n"
            "https://github.com/py4n6/pytsk/releases"
        )


# --------------------------------------------------------------------------
# EWF / E01 helper
# --------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).parent
_EWF_EXPORT  = _SCRIPT_DIR / "tools" / "ewf-tools" / "ewfexport.exe"
_EWF_INFO    = _SCRIPT_DIR / "tools" / "ewf-tools" / "ewfinfo.exe"

# Maximum time allowed for a single ewfexport run (seconds).
# 15 GiB at ~100 MiB/s = ~150 s; 7200 s gives huge headroom for slow storage.
_EWFEXPORT_TIMEOUT = 7200


def _ewfinfo_media_size(e01_path: str) -> Optional[int]:
    """Return the media size (bytes) stored in the E01 header, or None on failure."""
    ewfinfo = str(_EWF_INFO)
    if not os.path.isfile(ewfinfo):
        return None
    try:
        result = subprocess.run(
            [ewfinfo, e01_path],
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        for line in result.stdout.splitlines():
            # ewfinfo outputs: "\tMedia size:\t\t15 GiB (16172187648 bytes)"
            if "Media size" in line and "bytes" in line:
                import re
                m = re.search(r"\((\d+)\s+bytes\)", line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return None


def _ewfexport_to_raw(e01_path: str, dest_dir: str) -> str:
    """Convert E01 to raw DD via ewfexport.exe. Returns path to raw file.

    Hardening notes:
      - `-u`       : unattended mode — never prompts on stdin.
      - `-f raw`   : explicit output format so ewfexport never asks interactively.
      - stdin=DEVNULL : belt-and-suspenders; any residual stdin read gets EOF.
      - timeout    : hard wall-clock limit; a hung process is treated as failure.
      - size check : after exit-0, verifies raw file size == E01 media size so a
                     partial write (disk-full, process kill) is caught immediately.

    Root cause of previous silent hang: ewfexport without `-u` prompts for output
    format on stdin. Flask's subprocess wrapper buffered stdio, so it blocked until
    the 600 s timeout expired, produced no raw file, and every downstream pytsk3
    call failed with a misleading "high entropy / possible encryption" error.
    """
    ewf = str(_EWF_EXPORT)
    if not os.path.isfile(ewf):
        raise FileNotFoundError(f"ewfexport.exe not found at {ewf}")

    out_stem = os.path.join(dest_dir, "converted")

    # -u = unattended  -f raw = explicit raw format  (no interactive prompts)
    cmd = [ewf, "-u", "-f", "raw", "-t", out_stem, e01_path]

    log.info("ewfexport starting: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,   # belt-and-suspenders: no stdin at all
            timeout=_EWFEXPORT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"ewfexport timed out after {_EWFEXPORT_TIMEOUT}s — "
            "the process may have blocked on an unexpected prompt or the "
            "storage is too slow. Increase _EWFEXPORT_TIMEOUT or pre-convert "
            "the E01 to raw before uploading."
        )

    if result.returncode != 0:
        raise RuntimeError(
            f"ewfexport exited with code {result.returncode}. "
            f"stderr: {result.stderr[:800]}"
        )

    # Locate the output file (ewfexport names it <stem>.raw)
    raw_path = None
    for candidate in [out_stem + ".raw", out_stem + ".raw.000", out_stem]:
        if os.path.isfile(candidate):
            raw_path = candidate
            break

    if raw_path is None:
        raise FileNotFoundError(
            "ewfexport reported success but no output file found. "
            f"Expected one of: {out_stem}.raw, {out_stem}.raw.000"
        )

    # ── Size verification ────────────────────────────────────────────────────
    # A partial write (disk full, process killed before flush) can produce a
    # file smaller than the E01 media size. pytsk3 will misread it exactly as
    # a "high entropy / possible encryption" error — catch it here instead.
    actual_bytes = os.path.getsize(raw_path)
    expected_bytes = _ewfinfo_media_size(e01_path)

    if expected_bytes is not None:
        if actual_bytes != expected_bytes:
            # Remove the truncated file so a retry starts clean
            try:
                os.remove(raw_path)
            except OSError:
                pass
            raise RuntimeError(
                f"ewfexport output is {actual_bytes:,} bytes but E01 reports "
                f"{expected_bytes:,} bytes — partial write detected. "
                "Possible cause: disk full during export. Free space and retry."
            )
        log.info(
            "ewfexport size check passed: %s bytes (%s)",
            f"{actual_bytes:,}", raw_path
        )
    else:
        log.warning(
            "ewfinfo not available — skipping size check. "
            "Raw file is %s bytes.", f"{actual_bytes:,}"
        )

    log.info("ewfexport complete: %s", raw_path)
    return raw_path


# =============================================================================
# DISK IMAGE ANALYZER
# =============================================================================

class DiskImageAnalyzer:
    """
    Wraps pytsk3 to enumerate partitions and walk filesystems.
    All public methods call _require_tsk() first -- they raise ImportError
    immediately if pytsk3 is not installed. No silent fallback.
    """

    # ---- helpers ------------------------------------------------------------

    @staticmethod
    def _open_image(image_path: str) -> "pytsk3.Img_Info":
        _require_tsk()
        return pytsk3.Img_Info(image_path)

    @staticmethod
    def _ts_to_iso(ts_sec) -> Optional[str]:
        if not ts_sec:
            return None
        try:
            return datetime.fromtimestamp(int(ts_sec), tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None

    # ---- public API ---------------------------------------------------------

    @classmethod
    def convert_e01_to_raw(cls, e01_path: str, dest_dir: str) -> str:
        """Convert E01 image to raw DD. Returns path to raw file."""
        os.makedirs(dest_dir, exist_ok=True)
        return _ewfexport_to_raw(e01_path, dest_dir)

    @classmethod
    def list_partitions(cls, image_path: str) -> List[Dict[str, Any]]:
        """
        Return list of partition dicts:
          {index_num, type, start_sector, length_sectors, fs_type, description}

        Uses a four-level fallback chain to handle the wide variety of drone
        SD card layouts (no MBR, FAT32 direct at sector 0, exFAT, etc.):

          1. Standard Volume_Info partition table parse
          2. Whole-disk FS_Info auto-detect at offset 0
          3. Force-probe each filesystem type explicitly at offset 0
             (handles TSK's "high entropy" false-positive on FAT/exFAT)
          4. Try force-probe at common SD card sector offsets (63, 128, 2048, 8192)

        Only raises RuntimeError if all four strategies fail.
        """
        _require_tsk()
        img = cls._open_image(image_path)
        results = []

        FS_NAMES = {
            pytsk3.TSK_FS_TYPE_NTFS:  "NTFS",
            pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
            pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
            pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
            pytsk3.TSK_FS_TYPE_EXT3:  "ext3",
            pytsk3.TSK_FS_TYPE_EXT4:  "ext4",
            pytsk3.TSK_FS_TYPE_HFS:   "HFS+",
        }

        # ── Strategy 1: partition table (MBR/GPT) ────────────────────────────
        try:
            vol = pytsk3.Volume_Info(img)
            for part in vol:
                desc = part.desc.decode("utf-8", errors="replace").strip()
                fs_type = "unknown"
                try:
                    fs = pytsk3.FS_Info(img, offset=(part.start * 512))
                    fs_type = FS_NAMES.get(fs.info.ftype, f"type-{fs.info.ftype}")
                except Exception:
                    # Force-probe partition even if auto fails
                    fs_type = cls._force_probe_fs_type(img, part.start * 512, FS_NAMES)
                results.append({
                    "index_num":      part.addr,
                    "type":           desc,
                    "start_sector":   part.start,
                    "length_sectors": part.len,
                    "fs_type":        fs_type,
                    "description":    desc,
                })
            if results:
                return results
        except Exception:
            pass

        # ── Strategy 2: whole-disk auto-detect at offset 0 ───────────────────
        try:
            fs = pytsk3.FS_Info(img)
            fs_type = FS_NAMES.get(fs.info.ftype, f"type-{fs.info.ftype}")
            return [{
                "index_num": 0,
                "type": "whole-disk",
                "start_sector": 0,
                "length_sectors": 0,
                "fs_type": fs_type,
                "description": f"Whole-disk filesystem ({fs_type}, no partition table)",
            }]
        except Exception:
            pass

        # ── Strategy 3: force-probe known types at offset 0 ──────────────────
        # This is the main fix for the "high entropy" false-positive TSK raises
        # on drone SD cards (FAT32/exFAT direct at sector 0, no MBR).
        FORCE_TYPES = [
            (pytsk3.TSK_FS_TYPE_FAT32, "FAT32"),
            (pytsk3.TSK_FS_TYPE_FAT16, "FAT16"),
            (pytsk3.TSK_FS_TYPE_FAT12, "FAT12"),
            (pytsk3.TSK_FS_TYPE_NTFS,  "NTFS"),
            (pytsk3.TSK_FS_TYPE_EXT4,  "ext4"),
            (pytsk3.TSK_FS_TYPE_EXT3,  "ext3"),
            (pytsk3.TSK_FS_TYPE_HFS,   "HFS+"),
            (pytsk3.TSK_FS_TYPE_FAT_DETECT, "FAT"),
        ]
        for ftype, fname in FORCE_TYPES:
            try:
                pytsk3.FS_Info(img, offset=0, type=ftype)
                return [{
                    "index_num": 0,
                    "type": "whole-disk",
                    "start_sector": 0,
                    "length_sectors": 0,
                    "fs_type": fname,
                    "description": (
                        f"Whole-disk {fname} (forced detection — "
                        "TSK auto-detect bypassed due to high-entropy false-positive)"
                    ),
                }]
            except Exception:
                continue

        # ── Strategy 4: try common SD card data offsets ───────────────────────
        # Some SD images have a padding area before the filesystem
        SD_OFFSETS_SECTORS = [63, 128, 2048, 4096, 8192]
        for sector in SD_OFFSETS_SECTORS:
            offset = sector * 512
            for ftype, fname in FORCE_TYPES:
                try:
                    pytsk3.FS_Info(img, offset=offset, type=ftype)
                    return [{
                        "index_num": 0,
                        "type": f"offset-{sector}",
                        "start_sector": sector,
                        "length_sectors": 0,
                        "fs_type": fname,
                        "description": (
                            f"{fname} filesystem at sector {sector} "
                            "(non-standard SD card layout)"
                        ),
                    }]
                except Exception:
                    continue

        # All strategies exhausted
        raise RuntimeError(
            "Cannot parse partition table or filesystem after trying all detection "
            "strategies (Volume_Info, FS_Info auto, force-probe FAT32/NTFS/ext4, "
            "SD card offsets). The image may be encrypted, hardware-compressed "
            "at source, or a format not supported by TSK."
        )

    @classmethod
    def _force_probe_fs_type(cls, img, offset: int, fs_names: dict) -> str:
        """Try to force-open a filesystem at offset with each known type. Returns type name or 'unknown'."""
        for ftype, fname in [
            (pytsk3.TSK_FS_TYPE_FAT32, "FAT32"),
            (pytsk3.TSK_FS_TYPE_FAT16, "FAT16"),
            (pytsk3.TSK_FS_TYPE_NTFS,  "NTFS"),
            (pytsk3.TSK_FS_TYPE_FAT_DETECT, "FAT"),
            (pytsk3.TSK_FS_TYPE_EXT4,  "ext4"),
        ]:
            try:
                pytsk3.FS_Info(img, offset=offset, type=ftype)
                return fname
            except Exception:
                continue
        return "unknown"


    @classmethod
    def walk_filesystem(
        cls,
        image_path: str,
        start_sector: int,
        partition_id: int,
        image_id: int,
        batch_size: int = 500,
    ) -> Iterator[List[Dict[str, Any]]]:
        """
        Walk the filesystem starting at start_sector.

        YIELDS lists of file-entry dicts (batch_size per yield) -- designed for
        use with conn.executemany(); never yields one row at a time.

        Includes allocated, deleted, and orphan entries.
        Raises RuntimeError if the filesystem cannot be opened.
        """
        _require_tsk()
        img    = cls._open_image(image_path)
        offset = start_sector * 512

        # Try auto-detect first, then force-probe each known type (high-entropy fix)
        fs = None
        last_error = None
        FORCE_WALK_TYPES = [
            pytsk3.TSK_FS_TYPE_FAT32,
            pytsk3.TSK_FS_TYPE_FAT16,
            pytsk3.TSK_FS_TYPE_FAT12,
            pytsk3.TSK_FS_TYPE_FAT_DETECT,
            pytsk3.TSK_FS_TYPE_NTFS,
            pytsk3.TSK_FS_TYPE_EXT4,
            pytsk3.TSK_FS_TYPE_EXT3,
            pytsk3.TSK_FS_TYPE_HFS,
        ]
        try:
            fs = pytsk3.FS_Info(img, offset=offset)
        except Exception as e:
            last_error = e
            for ftype in FORCE_WALK_TYPES:
                try:
                    fs = pytsk3.FS_Info(img, offset=offset, type=ftype)
                    last_error = None
                    break
                except Exception:
                    continue

        if fs is None:
            raise RuntimeError(
                f"Cannot open filesystem at sector {start_sector} after trying "
                f"all known filesystem types: {last_error}"
            )

        def _meta_flag(meta, flag) -> bool:
            try:
                return bool(meta.flags & flag)
            except Exception:
                return False

        def _entry_to_dict(entry, dir_path: str) -> Optional[Dict[str, Any]]:
            try:
                name_info = entry.info.name
                name = name_info.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    return None

                is_dir = (name_info.type == pytsk3.TSK_FS_NAME_TYPE_DIR)
                full_path = dir_path.rstrip("/") + "/" + name
                meta = entry.info.meta

                alloc_status = "allocated"
                if meta:
                    if _meta_flag(meta, pytsk3.TSK_FS_META_FLAG_UNALLOC):
                        alloc_status = "deleted"
                    if _meta_flag(meta, pytsk3.TSK_FS_META_FLAG_ORPHAN):
                        alloc_status = "orphan"

                return {
                    "image_id":       image_id,
                    "partition_id":   partition_id,
                    "parent_id":      None,  # resolved by caller
                    "name":           name,
                    "full_path":      full_path,
                    "inode":          str(meta.addr) if meta else "",
                    "entry_type":     "dir" if is_dir else "file",
                    "size_bytes":     meta.size if meta else 0,
                    "alloc_status":   alloc_status,
                    "ts_created":     cls._ts_to_iso(meta.crtime if meta else None),
                    "ts_modified":    cls._ts_to_iso(meta.mtime  if meta else None),
                    "ts_accessed":    cls._ts_to_iso(meta.atime  if meta else None),
                    "ts_changed":     cls._ts_to_iso(meta.ctime  if meta else None),
                    "md5":            None,
                    "sha256":         None,
                    "extracted_path": None,
                }
            except Exception:
                return None

        batch: List[Dict[str, Any]] = []
        # Stack: (dir_object, path_prefix)
        dir_stack = [(fs.open_dir(path="/"), "/")]

        while dir_stack:
            dir_obj, dir_path = dir_stack.pop()
            try:
                for entry in dir_obj:
                    d = _entry_to_dict(entry, dir_path)
                    if d is None:
                        continue
                    batch.append(d)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
                    # Recurse into subdirectories
                    if d["entry_type"] == "dir":
                        try:
                            sub = entry.as_directory()
                            dir_stack.append((sub, d["full_path"]))
                        except Exception:
                            pass
            except Exception as e:
                log.warning("Error iterating dir '%s': %s", dir_path, e)

        if batch:
            yield batch

    @classmethod
    def extract_file(
        cls,
        image_path: str,
        start_sector: int,
        inode: str,
        dest_path: str,
    ) -> int:
        """
        Extract file by inode to dest_path. Returns bytes written.
        Raises on failure.
        """
        _require_tsk()
        img    = cls._open_image(image_path)
        offset = start_sector * 512
        fs     = pytsk3.FS_Info(img, offset=offset)

        f    = fs.open_meta(inode=int(inode))
        size = f.info.meta.size

        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        written = 0
        CHUNK   = 65536
        with open(dest_path, "wb") as out:
            pos = 0
            while pos < size:
                to_read = min(CHUNK, size - pos)
                data = f.read_random(pos, to_read)
                if not data:
                    break
                out.write(data)
                written += len(data)
                pos += len(data)
        return written

    @classmethod
    def detect_flight_logs(cls, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """From file-tree rows return those likely to be flight logs."""
        EXTS = {".dat", ".csv", ".kml", ".gpx", ".bin", ".log", ".tlog", ".txt"}
        PATS = ["telemetry", "flight", "gps", "log", "track", "waypoint",
                "mission", "mavlink", "dataflash"]
        SKIP_NAMES = {"volume label entry", "$mbr", "$fat1", "$fat2", "$orphanfiles",
                      "system volume information"}
        results = []
        seen = set()
        for row in rows:
            if row.get("entry_type") == "dir":
                continue
            name = (row.get("name") or "").lower()
            fid = row.get("id") or row.get("full_path")
            if fid in seen:
                continue
            # Skip volume labels, metadata entries, and system files
            if any(s in name for s in SKIP_NAMES):
                continue
            ext = os.path.splitext(name)[1]
            if ext in EXTS or any(p in name for p in PATS):
                results.append(row)
                seen.add(fid)
        return results


# =============================================================================
# FLIGHT LOG PARSER
# =============================================================================

class FlightParseError(Exception):
    """Raised when a flight log cannot be parsed. Always has a human-readable message."""
    pass


class FlightLogParser:
    """
    Parse flight logs into a normalized list of telemetry rows.

    Normalized schema per row (None for unavailable fields):
      ts           -- ISO timestamp or raw string
      lat          -- float, decimal degrees
      lon          -- float, decimal degrees
      alt_m        -- float, metres
      speed_ms     -- float, m/s
      heading      -- float, degrees
      battery_pct  -- float 0-100
      sats         -- int, satellite count
      mode         -- str, flight mode
    """

    _DATCON_JAR = None
    _DATCON_CANDIDATES = [
        _SCRIPT_DIR / "tools" / "DatCon" / "DatCon.jar",
        _SCRIPT_DIR / "tools" / "DatCon" / "DatCon.4.3.0.jar",
        _SCRIPT_DIR / "tools" / "DatCon.jar",
    ]
    for _c in _DATCON_CANDIDATES:
        if _c.is_file():
            _DATCON_JAR = str(_c)
            break

    @classmethod
    def parse(cls, filepath: str, fmt: Optional[str] = None) -> List[Dict[str, Any]]:
        """Auto-detect format from extension if fmt is None."""
        if fmt is None:
            fmt = cls._detect_fmt(filepath)
        parsers = {
            "csv":  cls._parse_csv,
            "gpx":  cls._parse_gpx,
            "kml":  cls._parse_kml,
            "bin":  cls._parse_ardubin,
            "log":  cls._parse_ardubin,
            "tlog": cls._parse_tlog,
            "dat":  cls._parse_dat,
            "srt":  cls._parse_srt,
            "txt":  cls._parse_csv,
        }
        fn = parsers.get(fmt)
        if fn is None:
            raise FlightParseError(f"Unsupported format: {fmt!r}")
        return fn(filepath)

    @staticmethod
    def _detect_fmt(filepath: str) -> str:
        return os.path.splitext(filepath)[1].lower().lstrip(".") or "csv"

    @staticmethod
    def _norm(**kw) -> Dict[str, Any]:
        return {k: kw.get(k) for k in
                ("ts","lat","lon","alt_m","speed_ms","heading","battery_pct","sats","mode")}

    # -- CSV ------------------------------------------------------------------
    @classmethod
    def _parse_csv(cls, filepath: str) -> List[Dict[str, Any]]:
        LAT  = {"latitude","lat","gps_lat","Latitude","Lat"}
        LON  = {"longitude","lon","gps_lon","Longitude","Lon"}
        ALT  = {"altitude","alt","altitude_m","rel_altitude","Altitude","Alt","height"}
        SPD  = {"speed","Speed","ground_speed","tas","velocity","groundspeed"}
        HDG  = {"heading","Heading","course","Course","yaw","Yaw","compass_heading"}
        BAT  = {"battery","Battery","battery_pct","battery_percent","voltage","batteryVoltage"}
        SAT  = {"satellites","Satellites","sats","gps_satellites","numSats"}
        MOD  = {"mode","Mode","flight_mode","FlightMode","flightMode"}
        TIME = {"timestamp","Timestamp","time","Time","datetime","Column1","datetime_utc",
                "time(millisecond)","GPS:dateTimeStamp"}

        rows = []
        with open(filepath, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise FlightParseError("CSV has no headers")
            cols = set(reader.fieldnames)

            def pick(s):
                for c in s:
                    if c in cols: return c
                return None

            c_ts  = pick(TIME)
            c_lat = pick(LAT)
            c_lon = pick(LON)
            c_alt = pick(ALT)
            c_spd = pick(SPD)
            c_hdg = pick(HDG)
            c_bat = pick(BAT)
            c_sat = pick(SAT)
            c_mod = pick(MOD)

            if not c_lat or not c_lon:
                raise FlightParseError(
                    "CSV has no recognisable latitude/longitude columns "
                    f"(found: {list(cols)[:10]}...)"
                )

            def f(r, c):
                try: return float(r[c]) if c else None
                except: return None

            def i(r, c):
                try: return int(float(r[c])) if c else None
                except: return None

            for row in reader:
                lat = f(row, c_lat)
                lon = f(row, c_lon)
                if lat is None or lon is None:
                    continue
                if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                    continue
                rows.append(cls._norm(
                    ts          = row[c_ts].strip() if c_ts and row.get(c_ts) else None,
                    lat         = lat,
                    lon         = lon,
                    alt_m       = f(row, c_alt),
                    speed_ms    = f(row, c_spd),
                    heading     = f(row, c_hdg),
                    battery_pct = f(row, c_bat),
                    sats        = i(row, c_sat),
                    mode        = row[c_mod].strip() if c_mod and row.get(c_mod) else None,
                ))
        return rows

    # -- GPX ------------------------------------------------------------------
    @classmethod
    def _parse_gpx(cls, filepath: str) -> List[Dict[str, Any]]:
        rows = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for trkpt in root.findall(".//{*}trkpt"):
                lat = float(trkpt.get("lat", 0))
                lon = float(trkpt.get("lon", 0))
                ele = trkpt.find("{*}ele")
                alt = float(ele.text) if ele is not None and ele.text else None
                t   = trkpt.find("{*}time")
                ts  = t.text if t is not None else None
                rows.append(cls._norm(lat=lat, lon=lon, alt_m=alt, ts=ts))
        except ET.ParseError as e:
            raise FlightParseError(f"GPX XML parse error: {e}")
        return rows

    # -- KML ------------------------------------------------------------------
    @classmethod
    def _parse_kml(cls, filepath: str) -> List[Dict[str, Any]]:
        rows = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for el in root.findall(".//{*}coordinates"):
                for chunk in (el.text or "").strip().split():
                    parts = chunk.split(",")
                    if len(parts) >= 2:
                        try:
                            lon = float(parts[0])
                            lat = float(parts[1])
                            alt = float(parts[2]) if len(parts) > 2 else None
                            rows.append(cls._norm(lat=lat, lon=lon, alt_m=alt))
                        except ValueError:
                            continue
        except ET.ParseError as e:
            raise FlightParseError(f"KML XML parse error: {e}")
        return rows

    # -- ArduPilot DataFlash --------------------------------------------------
    @classmethod
    def _parse_ardubin(cls, filepath: str) -> List[Dict[str, Any]]:
        try:
            from pymavlink import mavutil
        except ImportError:
            raise FlightParseError(
                "pymavlink not installed. Run: pip install pymavlink. "
                "Required for ArduPilot .bin/.log parsing."
            )
        rows = []
        try:
            mlog = mavutil.mavlink_connection(filepath, dialect="ardupilotmega")
            while True:
                msg = mlog.recv_match(
                    type=["GPS","GLOBAL_POSITION_INT","GPS_RAW_INT"],
                    blocking=False
                )
                if msg is None:
                    break
                t = msg.get_type()
                if t == "GPS":
                    lat = getattr(msg, "Lat", None)
                    lon = getattr(msg, "Lng", None)
                    alt = getattr(msg, "Alt", None)
                    spd = getattr(msg, "Spd", None)
                    if lat and lon:
                        rows.append(cls._norm(
                            lat=lat, lon=lon, alt_m=alt, speed_ms=spd,
                            sats=getattr(msg, "NSats", None)
                        ))
                elif t in ("GLOBAL_POSITION_INT", "GPS_RAW_INT"):
                    lat = getattr(msg,"lat",0)/1e7
                    lon = getattr(msg,"lon",0)/1e7
                    alt = getattr(msg,"alt",0)/1000.0
                    if lat and lon:
                        rows.append(cls._norm(lat=lat, lon=lon, alt_m=alt))
        except Exception as e:
            if not rows:
                raise FlightParseError(f"ArduPilot log parse failed: {e}")
        return rows

    # -- MAVLink .tlog --------------------------------------------------------
    @classmethod
    def _parse_tlog(cls, filepath: str) -> List[Dict[str, Any]]:
        try:
            from pymavlink import mavutil
        except ImportError:
            raise FlightParseError("pymavlink not installed. Required for .tlog parsing.")
        rows = []
        try:
            mlog = mavutil.mavlink_connection(filepath)
            while True:
                msg = mlog.recv_match(type="GLOBAL_POSITION_INT", blocking=False)
                if msg is None:
                    break
                lat = msg.lat / 1e7
                lon = msg.lon / 1e7
                alt = msg.alt / 1000.0
                if lat and lon:
                    rows.append(cls._norm(lat=lat, lon=lon, alt_m=alt))
        except Exception as e:
            if not rows:
                raise FlightParseError(f"MAVLink .tlog parse failed: {e}")
        return rows

    # -- DJI .DAT via DatCon.jar ----------------------------------------------
    @classmethod
    def _parse_dat(cls, filepath: str) -> List[Dict[str, Any]]:
        # Hard check: Java on PATH
        java = shutil.which("java")
        if java is None:
            raise FlightParseError(
                "Java not found on PATH. DatCon.jar requires Java to parse DJI .DAT files. "
                "Install Java (https://adoptium.net/) and ensure 'java' is in your system PATH, "
                "then restart the server."
            )
        if not cls._DATCON_JAR or not os.path.isfile(cls._DATCON_JAR):
            searched = "; ".join(str(p) for p in cls._DATCON_CANDIDATES)
            raise FlightParseError(
                f"DatCon.jar not found. Searched: {searched}. "
                "Download from https://datcon.org and place in tools/DatCon/"
            )

        with tempfile.TemporaryDirectory() as tmp:
            cmd = [java, "-jar", cls._DATCON_JAR, filepath, "--output-dir", tmp]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120
                )
            except subprocess.TimeoutExpired:
                raise FlightParseError("DatCon.jar timed out after 120 seconds")

            if result.returncode != 0:
                raise FlightParseError(
                    f"DatCon.jar exited with code {result.returncode}: "
                    f"{(result.stderr or result.stdout)[:400]}"
                )

            csvs = list(Path(tmp).glob("*.csv"))
            if not csvs:
                raise FlightParseError(
                    "DatCon.jar ran successfully but produced no CSV output. "
                    "The .DAT file may be from an unsupported firmware version."
                )

            all_rows: List[Dict[str, Any]] = []
            for csv_path in csvs:
                try:
                    all_rows.extend(cls._parse_csv(str(csv_path)))
                except FlightParseError:
                    pass

            if not all_rows:
                raise FlightParseError(
                    "DatCon CSV output contained no valid GPS rows."
                )
            return all_rows

    # -- DJI .SRT subtitle files ------------------------------------------------
    @classmethod
    def _parse_srt(cls, filepath: str) -> List[Dict[str, Any]]:
        """Parse DJI SRT subtitle files for embedded GPS telemetry.

        Typical SRT lines:
          [latitude: 25.123456] [longitude: 121.654321] [altitude: 123.4]
          [latitude: N 25° 04.1234] [longitude: E 121° 37.5678] [altitude: 123.4 m]
        """
        import re
        rows = []
        lat_re = re.compile(r'\[latitude:\s*([^\]]+)\]', re.I)
        lon_re = re.compile(r'\[longitude:\s*([^\]]+)\]', re.I)
        alt_re = re.compile(r'\[altitude:\s*([^\]]+)\]', re.I)

        def _parse_dms(val: str):
            """Parse 'N 25° 04.1234' or '25.123456' to decimal degrees."""
            val = val.strip()
            if not val:
                return None
            # Already decimal
            try:
                return float(val)
            except ValueError:
                pass
            # DMS format: N 25° 04.1234'
            m = re.match(r'([NSEW])\s*(\d+)[°\s]\s*(\d+(?:\.\d+)?)', val, re.I)
            if m:
                deg = float(m.group(2))
                minutes = float(m.group(3))
                dd = deg + minutes / 60.0
                if m.group(1).upper() in ('S', 'W'):
                    dd = -dd
                return dd
            return None

        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                lat_m = lat_re.search(line)
                lon_m = lon_re.search(line)
                alt_m = alt_re.search(line)
                if lat_m and lon_m:
                    lat = _parse_dms(lat_m.group(1))
                    lon = _parse_dms(lon_m.group(1))
                    if lat is not None and lon is not None and (-90 <= lat <= 90) and (-180 <= lon <= 180):
                        alt = None
                        if alt_m:
                            try:
                                alt = float(alt_m.group(1).split()[0])
                            except (ValueError, IndexError):
                                pass
                        rows.append(cls._norm(lat=lat, lon=lon, alt_m=alt))
        if not rows:
            raise FlightParseError(
                "SRT file contained no recognisable GPS coordinates."
            )
        return rows


# =============================================================================
# FLIGHT RECONSTRUCTOR
# =============================================================================

class FlightReconstructor:
    """
    Detect takeoff / landing from a normalized telemetry sequence and
    compute summary statistics.

    All threshold constants are defined here -- tune when real-world logs
    show noisy GPS/altitude data from specific drone models or environments.
    """

    # Metres above baseline altitude to consider the drone airborne (takeoff)
    TAKEOFF_AOM_M     = 2.0
    # Metres above baseline -- still airborne during landing detection
    LANDING_AOM_M     = 3.0
    # Consecutive readings required at/below LANDING_AOM_M to confirm landing
    LANDING_SUSTAIN_N = 5
    # Number of initial readings averaged to establish ground-level baseline
    BASELINE_WINDOW_N = 10
    # Maximum path points returned in path_json (thin for large logs)
    MAX_PATH_POINTS   = 2000

    @classmethod
    def reconstruct(cls, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Input:  normalized telemetry list from FlightLogParser.parse()
        Output: {takeoff, landing, path, stats, status, notes}

        status values:
          'complete' -- both takeoff and landing determined
          'partial'  -- one or both could not be determined (noted explicitly)
          'corrupt'  -- no usable GPS data at all
        """
        valid = [r for r in rows if r.get("lat") and r.get("lon")]
        if not valid:
            return {
                "takeoff": None, "landing": None,
                "path": [], "stats": {},
                "status": "corrupt",
                "notes": "No valid GPS rows found in this log.",
            }

        n       = len(valid)
        alts    = [float(r.get("alt_m") or 0) for r in valid]
        lats    = [float(r["lat"])   for r in valid]
        lons    = [float(r["lon"])   for r in valid]
        speeds  = [float(r.get("speed_ms") or 0) for r in valid]

        # Ground-level baseline from first N readings
        win      = min(cls.BASELINE_WINDOW_N, n)
        baseline = sum(alts[:win]) / win

        # -- Takeoff detection ------------------------------------------------
        takeoff_idx = None
        for i, a in enumerate(alts):
            if a > baseline + cls.TAKEOFF_AOM_M:
                takeoff_idx = i
                break

        # -- Landing detection ------------------------------------------------
        # Walk backward; require LANDING_SUSTAIN_N consecutive near-ground readings
        landing_idx = None
        for i in range(n - 1, -1, -1):
            end = min(i + cls.LANDING_SUSTAIN_N, n)
            window = alts[i:end]
            if (len(window) >= cls.LANDING_SUSTAIN_N and
                    all(a <= baseline + cls.LANDING_AOM_M for a in window)):
                landing_idx = i
                break

        # -- Status & notes ---------------------------------------------------
        notes_parts = []
        if takeoff_idx is None:
            notes_parts.append(
                "Takeoff point not recoverable "
                "(log may start mid-flight or altitude data is absent)."
            )
        if landing_idx is None:
            notes_parts.append(
                "Landing point not recoverable "
                "(log may end mid-flight or altitude data is absent)."
            )
        status = "complete" if not notes_parts else "partial"

        # -- Thinned path for map ---------------------------------------------
        step = max(1, n // cls.MAX_PATH_POINTS)
        path = [
            {"ts": valid[i].get("ts"), "lat": lats[i],
             "lon": lons[i], "alt_m": alts[i]}
            for i in range(0, n, step)
        ]

        # -- Derived statistics -----------------------------------------------
        def hav_m(la1, lo1, la2, lo2):
            R = 6_371_000
            f1, f2 = math.radians(la1), math.radians(la2)
            df = math.radians(la2 - la1)
            dl = math.radians(lo2 - lo1)
            a  = math.sin(df/2)**2 + math.cos(f1)*math.cos(f2)*math.sin(dl/2)**2
            return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        total_dist = sum(hav_m(lats[i-1],lons[i-1],lats[i],lons[i]) for i in range(1,n))
        max_alt    = max(alts) - baseline
        max_dist   = max(hav_m(lats[0],lons[0],lats[i],lons[i]) for i in range(n))
        pos_spd    = [s for s in speeds if 0 < s < 200]
        avg_spd    = sum(pos_spd)/len(pos_spd) if pos_spd else None
        max_spd    = max(pos_spd) if pos_spd else None

        def _parse_ts(s):
            if not s: return None
            for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S","%Y%m%d %H:%M:%S:%f"):
                try: return datetime.strptime(str(s).strip(), fmt)
                except ValueError: pass
            return None

        t0 = _parse_ts(valid[0].get("ts"))
        t1 = _parse_ts(valid[-1].get("ts"))
        dur = (t1 - t0).total_seconds() if t0 and t1 else None

        def _pt(idx):
            if idx is None: return None
            r = valid[idx]
            return {"lat": lats[idx], "lon": lons[idx],
                    "alt_m": alts[idx], "ts": r.get("ts")}

        return {
            "takeoff": _pt(takeoff_idx),
            "landing": _pt(landing_idx),
            "path":    path,
            "stats": {
                "duration_s":      dur,
                "max_alt_m":       round(max_alt, 2),
                "max_dist_m":      round(max_dist, 2),
                "total_dist_m":    round(total_dist, 2),
                "avg_speed_ms":    round(avg_spd, 2) if avg_spd else None,
                "max_speed_ms":    round(max_spd, 2) if max_spd else None,
                "point_count":     n,
                "baseline_alt_m":  round(baseline, 2),
            },
            "status": status,
            "notes":  " ".join(notes_parts) if notes_parts else None,
        }
