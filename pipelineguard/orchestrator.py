"""Bounded parallel file orchestration and progress telemetry."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, TypeVar

from pipelineguard.cache import ScanCache

T = TypeVar("T")


@dataclass(frozen=True)
class ProgressEvent:
    stage: str
    discovered: int = 0
    processed: int = 0
    cached: int = 0
    path: str | None = None


def fingerprint_files(
    root: Path,
    files: Iterable[Path],
    cache: ScanCache,
    *,
    workers: int = 4,
    progress: Callable[[ProgressEvent], None] | None = None,
) -> dict[str, str]:
    """Fingerprint files with bounded workers and emit UI/CLI-friendly events."""
    paths = list(files)
    if progress:
        progress(ProgressEvent("fingerprint", discovered=len(paths)))
    results: dict[str, str] = {}
    cached_count = 0
    live_keys = {cache.key_for(root, path) for path in paths}

    def fingerprint(path: Path) -> tuple[str, str, bool]:
        digest, reused = cache.digest(root, path)
        return cache.key_for(root, path), digest, reused

    with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="pipelineguard") as pool:
        futures = {pool.submit(fingerprint, path): path for path in paths}
        for processed, future in enumerate(as_completed(futures), start=1):
            key, digest, reused = future.result()
            results[key] = digest
            cached_count += int(reused)
            if progress:
                progress(ProgressEvent("fingerprint", len(paths), processed, cached_count, key))

    cache.prune(live_keys)
    cache.save()
    if progress:
        progress(ProgressEvent("fingerprint-complete", len(paths), len(paths), cached_count))
    return results
