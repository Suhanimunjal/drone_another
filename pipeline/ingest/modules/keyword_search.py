"""C6 — Keyword / Pattern Search.

Scans file content for regex patterns: emails, phones, IPs, MACs, crypto wallets, URLs.
Reads in chunks to handle large files.
"""

import os
import re
from ..base import IngestModule, Artifact

CHUNK_SIZE = 65536
MAX_FILE_SIZE = 100 * 1024 * 1024  # skip files > 100 MB

PATTERNS = [
    ("EMAIL", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ("PHONE", r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}"),
    ("IPV4", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    ("IPV6", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    ("MAC", r"(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}"),
    ("BTC", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    ("ETH", r"\b0x[a-fA-F0-9]{40}\b"),
    ("URL", r"https?://[^\s<>\"']+"),
    ("CREDIT_CARD", r"\b(?:\d[ -]*?){13,16}\b"),
]

COMPILED = [(name, re.compile(pat, re.IGNORECASE)) for name, pat in PATTERNS]

TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".xml", ".json", ".html", ".htm",
                   ".ini", ".cfg", ".conf", ".srt", ".md", ".yml", ".yaml",
                   ".sql", ".php", ".py", ".js", ".bat", ".sh"}


def _is_text_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(1024)
        return not bool(head.translate(None, bytes(range(32, 127)) + b"\n\r\t"))
    except Exception:
        return False


def _scan_file(path, max_size=MAX_FILE_SIZE):
    """Scan file for all keyword patterns. Returns list of (pattern_name, matched_text, byte_offset)."""
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return []
    except OSError:
        return []

    if not _is_text_file(path):
        return []

    hits = []
    try:
        with open(path, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                try:
                    text = chunk.decode("utf-8", errors="replace")
                except Exception:
                    text = chunk.decode("latin-1", errors="replace")
                for name, regex in COMPILED:
                    for m in regex.finditer(text):
                        hits.append((name, m.group(), offset + m.start()))
                offset += len(chunk)
    except Exception:
        pass

    # Deduplicate overlapping hits, keep first occurrence per unique pattern+text
    seen = set()
    deduped = []
    for name, text, off in hits:
        key = (name, text)
        if key not in seen:
            seen.add(key)
            deduped.append((name, text, off))
    return deduped


class KeywordSearchModule(IngestModule):
    name = "keyword_search"
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

        hits = _scan_file(file_path)
        if not hits:
            return []

        results = []
        for name, matched_text, byte_offset in hits:
            results.append(Artifact(
                artifact_type="TSK_KEYWORD_HIT",
                case_id=case_id,
                module_name=self.name,
                file_id=file_id,
                severity="low" if name in ("URL", "EMAIL") else "medium",
                title=f"[{name}] {matched_text[:60]}",
                description=f"Pattern '{name}' matched in {os.path.basename(rel_path)}",
                matched_text=matched_text,
                byte_offset=byte_offset,
                details={
                    "pattern_name": name,
                    "matched_text": matched_text,
                    "byte_offset": byte_offset,
                    "context_file": rel_path,
                },
            ))
        return results
