"""C3 — Hash Set Filtering (NSRL / custom known / known-bad).

Requires a hash lookup path in config. Flags files matching known-good
(to skip in later modules) and known-bad (malware/contraband hit).
"""

import os
import hashlib
import json
import csv
from ..base import IngestModule, Artifact

# Paths checked for hash set files (in order of preference)
HASH_SET_CANDIDATES = [
    "hash_sets/nsrl/NSRLFile.txt",          # NIST NSRL
    "hash_sets/known-good.txt",              # Custom known-good (MD5, one per line)
    "hash_sets/known-bad.txt",               # Custom known-bad (MD5, one per line)
    "../hash_sets/nsrl/NSRLFile.txt",
]

BLOCK_SIZE = 65536


def _file_md5(path):
    """Compute MD5 of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(BLOCK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def _load_nsrl(path):
    """Load NSRL MD5 set from the tab-delimited NSRLFile.txt."""
    hashes = set()
    try:
        with open(path, "r", encoding="latin-1") as f:
            reader = csv.reader(f, delimiter="\t")
            for row in reader:
                if len(row) >= 1 and row[0].strip():
                    hashes.add(row[0].strip().upper())
    except Exception:
        pass
    return hashes


def _load_hash_file(path):
    """Load one-md5-per-line file (case-insensitive, skip blanks/comments)."""
    hashes = set()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith(";"):
                    hashes.add(line.upper())
    except Exception:
        pass
    return hashes


def _discover_hash_sets():
    """Find available hash sets. Returns dict of name -> set of MD5 hashes."""
    sets = {}

    for cand in HASH_SET_CANDIDATES:
        resolved = os.path.join(os.getcwd(), cand)
        if not os.path.isfile(resolved):
            # Check relative to this file's dir too
            resolved = os.path.join(os.path.dirname(__file__), "..", "..", "..", cand)
            if not os.path.isfile(resolved):
                continue

        if "nsrl" in cand.lower():
            sets["NSRL"] = _load_nsrl(resolved)
        elif "known-good" in cand.lower():
            sets["known_good"] = _load_hash_file(resolved)
        elif "known-bad" in cand.lower():
            sets["known_bad"] = _load_hash_file(resolved)

    return sets


class HashFilterModule(IngestModule):
    name = "hash_filter"
    depends_on = []
    applies_to = "all_files"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        file_path = file_manifest_row.get("extracted_path")
        if not file_path or not os.path.isfile(file_path):
            return []

        # Compute MD5
        try:
            md5 = _file_md5(file_path)
        except Exception:
            return []

        artifacts = []
        sets = _discover_hash_sets()

        if "known_bad" in sets and md5 in sets["known_bad"]:
            artifacts.append(Artifact(
                artifact_type="TSK_HASH_HIT",
                case_id=file_manifest_row.get("case_id"),
                module_name=self.name,
                file_id=file_manifest_row.get("id"),
                severity="high",
                title="Known-bad hash hit",
                description=f"MD5 {md5} matches known-bad set",
                hash_value=md5,
                details={"hash_set": "known_bad", "md5": md5},
            ))

        if "known_good" in sets and md5 in sets["known_good"]:
            artifacts.append(Artifact(
                artifact_type="TSK_HASH_HIT",
                case_id=file_manifest_row.get("case_id"),
                module_name=self.name,
                file_id=file_manifest_row.get("id"),
                severity="info",
                title="Known-good (NSRL hit)" if "NSRL" in sets and md5 in sets.get("NSRL", set()) else "Known-good hash hit",
                description=f"MD5 {md5} matches known-good / NSRL set",
                hash_value=md5,
                details={"hash_set": "known_good", "md5": md5},
                ignore_in_ui=False,
            ))

        if "NSRL" in sets and md5 in sets["NSRL"]:
            artifacts.append(Artifact(
                artifact_type="TSK_HASH_HIT",
                case_id=file_manifest_row.get("case_id"),
                module_name=self.name,
                file_id=file_manifest_row.get("id"),
                severity="info",
                title="NSRL known-good hit",
                description=f"MD5 {md5} is in NIST NSRL; may be admissible",
                hash_value=md5,
                details={"hash_set": "NSRL", "md5": md5},
                ignore_in_ui=False,
            ))

        return artifacts
