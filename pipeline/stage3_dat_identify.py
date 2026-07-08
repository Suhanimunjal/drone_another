"""Stage 3: DAT File Identification

Classifies extracted files by path/extension to identify DAT flight logs.
No magic-byte sniffing — path-based classification per spec.

Input: file manifest from Stage 2
Output: updated file_type field in manifest
"""

from . import manifest_db


# ── Classification rules (spec section 3 — exact, deterministic) ─────────

def classify_file(path):
    """Classify a file by path/extension. Returns file_type string."""
    upper = path.upper()

    # DAT flight logs (DJI specific)
    if upper.endswith(".DAT"):
        if "FLY" in upper or "DJI" in upper or "/FLIGHTLOG" in upper:
            return "DAT_LOG"
        return "DAT_UNKNOWN"

    # SRT subtitle/caption logs
    if upper.endswith(".SRT"):
        return "CAPTION_LOG"

    # Keychain files
    if upper.endswith(".TXT") and "KEYCHAIN" in upper:
        return "KEYCHAIN_FILE"

    # Other known types for reference
    if upper.endswith((".MP4", ".MOV")):
        return "VIDEO"
    if upper.endswith((".JPG", ".JPEG", ".PNG", ".DNG")):
        return "IMAGE"
    if upper.endswith((".CSV",)):
        return "CSV_DATA"
    if upper.endswith((".BIN",)):
        return "BIN_DATA"
    if upper.endswith((".LOG",)):
        return "LOG_FILE"
    if upper.endswith((".CFG", ".PARAM", ".XML", ".INI")):
        return "CONFIG"

    return "OTHER"


def run_stage3(case_id, log_cb=None):
    """Execute Stage 3: classify all files, identify DAT_LOG files.

    Args:
        case_id: case UUID
        log_cb: optional callback(level, message)

    Returns:
        dict with classification stats
    """
    def log(level, msg):
        if log_cb:
            log_cb(level, msg)
        print(f"[Stage 3] [{level}] {msg}")

    log("stage", "Classifying files")

    files = manifest_db.get_case_files(case_id)
    stats = {"total": len(files), "dat_log": 0, "dat_unknown": 0, "other": 0}
    dat_files = []

    for f in files:
        file_type = classify_file(f["path"])
        manifest_db.update_file_type(f["id"], file_type)

        if file_type == "DAT_LOG":
            stats["dat_log"] += 1
            dat_files.append(f)
        elif file_type == "DAT_UNKNOWN":
            stats["dat_unknown"] += 1
        else:
            stats["other"] += 1

    log("info", f"Total files: {stats['total']}")
    log("info", f"DAT_LOG (flight logs): {stats['dat_log']}")
    log("info", f"DAT_UNKNOWN (manual review): {stats['dat_unknown']}")
    log("info", f"Other: {stats['other']}")

    if dat_files:
        for df in dat_files:
            log("info", f"  -> {df['path']} ({df['size_bytes']} bytes)")

    manifest_db.update_case_stage(case_id, "stage3", 50)

    return {"stats": stats, "dat_files": dat_files}
