"""Stage 1: Image Format Detection & Universal Mount

Detects disk image format by magic bytes (extension is fallback only).
Mounts/accesses the image to produce a raw block handle for Stage 2.

Output: case_metadata.json with block_access_path.
"""

import os
import struct
import subprocess
import tempfile
import shutil
from pathlib import Path

from . import manifest_db

# Add tools directories to PATH for subprocess calls
_tools_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
_ewf_tools_dir = os.path.join(_tools_dir, "ewf-tools")
if os.path.isdir(_ewf_tools_dir) and _ewf_tools_dir not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _ewf_tools_dir + os.pathsep + os.environ.get("PATH", "")


# ── Magic byte signatures (spec section 1a) ──────────────────────────────

MAGIC_SIGNATURES = {
    b"EVF\x09\x0d\x0a\xff\x00":  "EWF",
    b"EVF2\x0d\x0a\x91\x0a":     "EWF2",
    b"AFF\x0a":                   "AFF",
    b"KDMV":                      "VMDK",
    b"conectix":                  "VHD",
    b"vhdxfile":                  "VHDX",
}

RAW_EXTENSIONS = {"dd", "raw", "img", "bin", "001"}
ISO_EXTENSIONS = {"iso"}
EWF_EXTENSIONS = {"e01", "ex01"}
EWF_LOGICAL_EXTENSIONS = {"l01"}
AFF_EXTENSIONS = {"aff", "aff4"}
VMDK_EXTENSIONS = {"vmdk"}
VHD_EXTENSIONS = {"vhd"}
VHDX_EXTENSIONS = {"vhdx"}


def detect_format(file_path):
    """Detect image format by magic bytes first, extension as fallback.

    Returns format string per spec.
    """
    with open(file_path, "rb") as f:
        head = f.read(16)

    # Magic byte check (authoritative)
    for magic, fmt in MAGIC_SIGNATURES.items():
        if head.startswith(magic):
            return fmt

    # Extension fallback (only if magic bytes didn't match)
    ext = Path(file_path).suffix.lower().lstrip(".")
    if ext in RAW_EXTENSIONS:
        return "RAW"
    if ext in ISO_EXTENSIONS:
        return "ISO"
    if ext in EWF_EXTENSIONS:
        return "EWF"
    if ext in EWF_LOGICAL_EXTENSIONS:
        return "EWF_LOGICAL"
    if ext in AFF_EXTENSIONS:
        return "AFF"
    if ext in VMDK_EXTENSIONS:
        return "VMDK"
    if ext in VHD_EXTENSIONS:
        return "VHD"
    if ext in VHDX_EXTENSIONS:
        return "VHDX"

    # Last resort: ask qemu-img
    return _detect_via_qemu_img(file_path)


def _detect_via_qemu_img(file_path):
    """Ask qemu-img for format detection."""
    try:
        result = subprocess.run(
            ["qemu-img", "info", file_path],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            if line.strip().startswith("file format:"):
                fmt = line.split(":", 1)[1].strip().upper()
                return f"QEMU_{fmt}"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "UNKNOWN"


# ── Mount/access commands (spec section 1b) ──────────────────────────────

def mount_image(file_path, output_dir, fmt):
    """Mount/access the image based on detected format.

    Returns (block_access_path, format_label, extra_metadata).
    Raises RuntimeError on failure.
    """
    file_path = str(file_path)
    output_dir = str(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    if fmt in ("EWF", "EWF2"):
        return _mount_ewf(file_path, output_dir)
    elif fmt == "EWF_LOGICAL":
        return _mount_ewf_logical(file_path, output_dir)
    elif fmt == "AFF":
        return _mount_aff(file_path, output_dir)
    elif fmt == "RAW":
        return (file_path, "RAW", {})
    elif fmt == "ISO":
        return _mount_iso(file_path, output_dir)
    elif fmt in ("VMDK", "VHD", "VHDX"):
        return _mount_qemu_nbd(file_path, output_dir, fmt)
    elif fmt.startswith("QEMU_"):
        # Re-dispatch based on qemu-detected format
        inner_fmt = fmt.replace("QEMU_", "")
        if inner_fmt in ("RAW", "VDI", "VMDK", "VHD", "VHDX"):
            if inner_fmt == "RAW":
                return (file_path, "RAW_QEMU", {})
            return _mount_qemu_nbd(file_path, output_dir, inner_fmt)
        return (file_path, fmt, {})
    else:
        raise RuntimeError(f"Cannot mount image format: {fmt}")


def _mount_ewf(file_path, output_dir):
    """Mount/convert E01 to raw block access.

    Tries: ewfmount -> ewfexport -> pyewf
    """
    mount_dir = os.path.join(output_dir, "ewf_mount")
    os.makedirs(mount_dir, exist_ok=True)

    # Try ewfmount (FUSE mount)
    try:
        subprocess.run(
            ["ewfmount", file_path, mount_dir],
            capture_output=True, text=True, timeout=120, check=True
        )
        raw_path = os.path.join(mount_dir, "ewf1")
        if os.path.exists(raw_path):
            return (raw_path, "EWF", {"mount_dir": mount_dir})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    # Fallback: ewfexport to raw
    raw_path = os.path.join(output_dir, "ewf_raw.dd")
    try:
        subprocess.run(
            ["ewfexport", "-u", "-f", "raw",
             "-t", os.path.join(output_dir, "ewf_raw"),
             file_path],
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL,
            timeout=7200, check=True
        )
        # ewfexport produces ewf_raw.raw
        for candidate in [raw_path, os.path.join(output_dir, "ewf_raw.raw")]:
            if os.path.exists(candidate):
                return (candidate, "EWF (exported raw)", {})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    # Fallback: try pyewf if available
    try:
        import pyewf
        handle = pyewf.handle()
        handle.open(file_path)
        # Export via pyewf
        raw_path = os.path.join(output_dir, "ewf_pyraw.dd")
        chunk_size = 1024 * 1024
        chunk_no = 0
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            # Write in append mode
            mode = "ab" if chunk_no > 0 else "wb"
            with open(raw_path, mode) as f:
                f.write(chunk)
            chunk_no += 1
        handle.close()
        if os.path.exists(raw_path):
            return (raw_path, "EWF (pyewf export)", {})
    except ImportError:
        pass

    raise RuntimeError(
        "E01 images require ewf-tools (ewfmount or ewfexport). "
        "Install from: https://github.com/Positronikal/ewf-tools-win64"
    )


def _mount_ewf_logical(file_path, output_dir):
    """Handle L01 logical evidence — no partition table, files only."""
    # L01 is a logical image — TSK can read it directly but no mmls step
    return (file_path, "EWF_LOGICAL", {"skip_partition": True})


def _mount_aff(file_path, output_dir):
    """Mount AFF via affuse."""
    mount_dir = os.path.join(output_dir, "aff_mount")
    os.makedirs(mount_dir, exist_ok=True)

    try:
        subprocess.run(
            ["affuse", file_path, mount_dir],
            capture_output=True, text=True, timeout=120, check=True
        )
        base = Path(file_path).stem
        raw_path = os.path.join(mount_dir, f"{base}.raw")
        if os.path.exists(raw_path):
            return (raw_path, "AFF", {"mount_dir": mount_dir})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    # Fallback: convert to raw
    try:
        raw_path = os.path.join(output_dir, f"{Path(file_path).stem}.raw")
        subprocess.run(
            ["affconvert", "-o", raw_path, file_path],
            capture_output=True, text=True, timeout=600, check=True
        )
        if os.path.exists(raw_path):
            return (raw_path, "AFF Converted", {})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    raise RuntimeError("AFF images require afflib-tools (affuse/affconvert)")


def _mount_iso(file_path, output_dir):
    """Mount ISO via loop mount (Linux) or copy contents (Windows)."""
    mount_dir = os.path.join(output_dir, "iso_mount")
    os.makedirs(mount_dir, exist_ok=True)

    if os.name == "nt":
        # Windows: use 7z or PowerShell to extract ISO
        try:
            subprocess.run(
                ["7z", "x", file_path, f"-o{mount_dir}", "-y"],
                capture_output=True, text=True, timeout=300, check=True
            )
            return (mount_dir, "ISO", {"skip_partition": True, "extracted": True})
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        raise RuntimeError("ISO extraction requires 7-Zip on Windows")
    else:
        try:
            subprocess.run(
                ["mount", "-o", "loop,ro", file_path, mount_dir],
                capture_output=True, text=True, timeout=30, check=True
            )
            return (mount_dir, "ISO", {"skip_partition": True, "mount_dir": mount_dir})
        except (FileNotFoundError, subprocess.CalledProcessError):
            raise RuntimeError("ISO mount failed")


def _mount_qemu_nbd(file_path, output_dir, fmt):
    """Mount VMDK/VHD/VHDX via qemu-nbd."""
    # On Windows, qemu-nbd may not work without WSL/Linux
    # Fallback: use qemu-img to convert to raw
    raw_path = os.path.join(output_dir, f"{Path(file_path).stem}.raw")

    try:
        subprocess.run(
            ["qemu-img", "convert", "-f", fmt.lower(), "-O", "raw",
             file_path, raw_path],
            capture_output=True, text=True, timeout=600, check=True
        )
        if os.path.exists(raw_path):
            return (raw_path, f"{fmt} Converted", {})
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        raise RuntimeError(f"Cannot convert {fmt} image: {e}")


# ── Integrity hash computation (spec section 1c) ─────────────────────────

def compute_hash(file_path, algorithm="sha256"):
    """Compute hash of a file."""
    import hashlib
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_ewf_metadata(file_path):
    """Extract embedded hashes from EWF image via ewfinfo."""
    try:
        result = subprocess.run(
            ["ewfinfo", file_path],
            capture_output=True, text=True, timeout=30
        )
        metadata = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                if "md5" in key:
                    metadata["md5"] = val
                elif "sha1" in key:
                    metadata["sha1"] = val
                elif "acquisition" in key and "date" in key:
                    metadata["acquisition_date"] = val
                elif "media" in key and "size" in key:
                    try:
                        metadata["media_size_bytes"] = int(val.replace(",", ""))
                    except ValueError:
                        pass
        return metadata
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}


# ── Main entry point (spec section 1) ────────────────────────────────────

def run_stage1(file_path, case_id, output_dir):
    """Execute Stage 1: detect format, mount, compute hashes, store metadata.

    Args:
        file_path: path to the disk image
        case_id: UUID for this case
        output_dir: working directory for this case

    Returns:
        dict with case_metadata fields
    """
    file_path = str(file_path)
    os.makedirs(output_dir, exist_ok=True)

    # 1. Detect format
    detected_format = detect_format(file_path)
    print(f"[Stage 1] Detected format: {detected_format}")

    # 2. Mount/access
    mount_point, format_label, extra = mount_image(file_path, output_dir, detected_format)
    print(f"[Stage 1] Block access path: {mount_point}")

    # 3. Compute integrity hash
    hash_algorithm = "sha256"
    hash_source = "computed"

    # Try embedded hash first (EWF/AFF)
    if detected_format in ("EWF", "EWF2"):
        ewf_meta = get_ewf_metadata(file_path)
        if ewf_meta.get("md5"):
            hash_value = ewf_meta["md5"]
            hash_algorithm = "md5"
            hash_source = "embedded"
        else:
            hash_value = compute_hash(file_path)
    elif detected_format == "AFF":
        hash_value = compute_hash(file_path)  # affinfo not reliably available
    else:
        hash_value = compute_hash(file_path)

    # 4. Get media size
    media_size = os.path.getsize(file_path)
    acquisition_date = extra.get("acquisition_date")

    # 5. Store in DB
    manifest_db.insert_case(
        case_id=case_id,
        source_file=os.path.basename(file_path),
        detected_format=detected_format,
        hash_algorithm=hash_algorithm,
        hash_value=hash_value,
        hash_source=hash_source,
        media_size_bytes=media_size,
        block_access_path=mount_point,
    )

    # Write case_metadata.json
    metadata = {
        "case_id": case_id,
        "source_file": os.path.basename(file_path),
        "detected_format": detected_format,
        "format_label": format_label,
        "hash_algorithm": hash_algorithm,
        "hash_value": hash_value,
        "hash_source": hash_source,
        "acquisition_date": acquisition_date,
        "media_size_bytes": media_size,
        "block_access_path": mount_point,
        "extra": extra,
    }
    meta_path = os.path.join(output_dir, "case_metadata.json")
    import json
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[Stage 1] Complete: {detected_format}, hash={hash_value[:16]}...")
    return metadata
