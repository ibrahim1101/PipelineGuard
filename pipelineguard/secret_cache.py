"""Content-verified local secret finding cache; never stores secret values."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from itertools import islice
from typing import Callable
from scanners.secret_scanner import RULES, scan_text, scan_directory
from scanners.traversal import iter_files

# Files smaller than this cost less to scan than to hash and cache on typical SSDs.
# This is an experimental threshold pending platform-specific benchmarks.
MIN_CACHE_BYTES = 1024



def _safe_cached_findings(value: object, relative: str) -> bool:
    """Reject malformed/tampered cache entries; do not trust external JSON."""
    if not isinstance(value, list):
        return False
    return all(
        isinstance(item, dict)
        and set(item) == {"severity", "rule", "confidence", "file", "line"}
        and item["severity"] == "CRITICAL"
        and item["rule"] in {name for name, _ in RULES}
        and item["confidence"] in {"high", "medium"}
        and item["file"] == relative
        and type(item["line"]) is int and item["line"] > 0
        for item in value
    )

def choose_scan_strategy(root: Path, ignored_directories: set[str], max_file_size: int, *, sample_size: int = 64) -> str:
    """Sample file sizes without trusting metadata for secret detection.

    Select full scanning only for overwhelmingly tiny-file repositories.
    Any sampling error falls back to the verified incremental scanner.
    """
    try:
        sizes = []
        for path in islice(iter_files(root.resolve(), ignored_directories), sample_size):
            size = path.stat().st_size
            if size <= max_file_size:
                sizes.append(size)
        if len(sizes) >= 32 and sum(size < MIN_CACHE_BYTES for size in sizes) * 10 >= len(sizes) * 9:
            return "full"
    except OSError:
        pass
    return "incremental"


def scan_secrets_incremental(root: Path, ignored_directories: set[str], max_file_size: int, *, metrics: dict[str, int] | None = None, on_finding: Callable[[dict[str, object]], None] | None = None) -> list[dict[str, object]]:
    root = root.resolve()
    signature = hashlib.sha256(repr([(name, regex.pattern, regex.flags) for name, regex in RULES]).encode()).hexdigest()
    base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    store = base / "PipelineGuard" / "secret-findings" / (hashlib.sha256(os.fsencode(str(root))).hexdigest() + ".json")
    try:
        cache = json.loads(store.read_text(encoding="utf-8"))
        if not isinstance(cache, dict) or cache.get("version") != 1 or cache.get("signature") != signature or cache.get("limit") != max_file_size:
            cache = {}
    except (OSError, ValueError, TypeError):
        cache = {}
    previous = cache.get("files", {}) if isinstance(cache.get("files"), dict) else {}
    cache_dirty = cache.get("version") != 1 or cache.get("min_cache_bytes") != MIN_CACHE_BYTES
    # Cache entries are only hints: unchanged metadata is insufficient for trust.
    # Continue hashing content to detect same-size/same-mtime modifications.
    updated = {}
    results = []
    counts = {"discovered": 0, "hashed": 0, "scanned": 0, "reused": 0,
              "skipped_size": 0, "skipped_changed": 0, "skipped_error": 0}
    for file_path in iter_files(root, ignored_directories):
        counts["discovered"] += 1
        relative = str(file_path.relative_to(root))
        try:
            before = file_path.stat()
            if before.st_size > max_file_size:
                counts["skipped_size"] += 1
                continue
            if before.st_size < MIN_CACHE_BYTES:
                # Scan tiny files directly; no hash, cache lookup or persistence.
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                findings = scan_text(content, relative)
                final = file_path.stat()
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns, final.st_ino):
                    counts["skipped_changed"] += 1
                    continue
                counts["scanned"] += 1
                results.extend(findings)
                if on_finding is not None:
                    for finding in findings:
                        on_finding(dict(finding))
                continue
            # Retain bounded content for hashing and cache-miss scanning.
            with file_path.open("rb") as handle:
                content_bytes = handle.read(max_file_size + 1)
            if len(content_bytes) > max_file_size:
                counts["skipped_size"] += 1
                continue
            fingerprint = hashlib.sha256(content_bytes).hexdigest()
            after = file_path.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino):
                counts["skipped_changed"] += 1
                continue
            counts["hashed"] += 1
            prior = previous.get(relative)
            if (isinstance(prior, dict) and prior.get("sha256") == fingerprint and
                _safe_cached_findings(prior.get("findings"), relative)):
                findings = prior["findings"]
                counts["reused"] += 1
            else:
                cache_dirty = True
                findings = scan_text(content_bytes.decode("utf-8", errors="ignore"), relative)
                final = file_path.stat()
                if (final.st_size, final.st_mtime_ns, final.st_ctime_ns, final.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino):
                    counts["skipped_changed"] += 1
                    continue
                counts["scanned"] += 1
            updated[relative] = {"sha256": fingerprint, "findings": findings}
            results.extend(findings)
            if on_finding is not None:
                for finding in findings:
                    on_finding(dict(finding))
        except (OSError, UnicodeError):
            counts["skipped_error"] += 1
            continue
    if metrics is not None:
        metrics.update(counts)
    # Avoid rewriting a large cache JSON file on every unchanged warm scan.
    if not cache_dirty and len(updated) == len(previous) and updated.keys() == previous.keys():
        return results
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        temporary = store.with_suffix(".tmp")
        temporary.write_text(json.dumps({"version": 1, "signature": signature, "limit": max_file_size, "min_cache_bytes": MIN_CACHE_BYTES, "files": updated}), encoding="utf-8")
        temporary.replace(store)
    except OSError:
        pass
    return results
