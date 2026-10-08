"""Content-verified local secret finding cache; never stores secret values."""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
from scanners.secret_scanner import RULES, scan_file
from scanners.traversal import iter_files

def scan_secrets_incremental(root: Path, ignored_directories: set[str], max_file_size: int) -> list[dict[str, object]]:
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
    updated = {}
    results = []
    for file_path in iter_files(root, ignored_directories):
        relative = str(file_path.relative_to(root))
        try:
            before = file_path.stat()
            if before.st_size > max_file_size:
                continue
            digest = hashlib.sha256()
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(131072), b""):
                    digest.update(chunk)
            after = file_path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                continue
            fingerprint = digest.hexdigest()
            prior = previous.get(relative)
            if (isinstance(prior, dict) and prior.get("sha256") == fingerprint and
                isinstance(prior.get("findings"), list) and
                all(isinstance(x, dict) and set(x) == {"severity", "rule", "confidence", "file", "line"}
                    and x.get("file") == relative and isinstance(x.get("line"), int)
                    for x in prior["findings"])):
                findings = prior["findings"]
            else:
                findings = scan_file(file_path, root, max_file_size)
                final = file_path.stat()
                if (final.st_size, final.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    continue
            updated[relative] = {"sha256": fingerprint, "findings": findings}
            results.extend(findings)
        except (OSError, UnicodeError):
            continue
    try:
        store.parent.mkdir(parents=True, exist_ok=True)
        temporary = store.with_suffix(".tmp")
        temporary.write_text(json.dumps({"version": 1, "signature": signature, "limit": max_file_size, "files": updated}), encoding="utf-8")
        temporary.replace(store)
    except OSError:
        pass
    return results
