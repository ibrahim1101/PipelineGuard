"""Bounded parallel file orchestration and progress telemetry."""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from pipelineguard.cache import ScanCache


@dataclass(frozen=True)
class ProgressEvent:
    stage: str
    discovered: int | None = 0
    processed: int | None = 0
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
    """Hash streaming input with at most 2*workers pending futures.

    Results and persistent cache remain O(file count); the task queue is
    bounded. This is not yet a constant-memory million-file scanner.
    """
    worker_count = max(1, workers)
    max_pending = worker_count * 2
    source = iter(files)
    results: dict[str, str] = {}
    live_keys: set[str] = set()
    discovered = processed = cached_count = 0

    def fingerprint(path: Path) -> tuple[str, str, bool]:
        digest, reused = cache.digest(root, path)
        return cache.key_for(root, path), digest, reused

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="pipelineguard") as pool:
        pending = set()

        def fill_queue() -> None:
            nonlocal discovered
            while len(pending) < max_pending:
                try:
                    path = next(source)
                except StopIteration:
                    return
                live_keys.add(cache.key_for(root, path))
                pending.add(pool.submit(fingerprint, path))
                discovered += 1

        fill_queue()
        if progress:
            progress(ProgressEvent("fingerprint", discovered=discovered))
        while pending:
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                key, digest, reused = future.result()
                results[key] = digest
                processed += 1
                cached_count += int(reused)
                if progress:
                    progress(ProgressEvent("fingerprint", discovered, processed, cached_count, key))
            fill_queue()

    cache.prune(live_keys)
    cache.save()
    if progress:
        progress(ProgressEvent("fingerprint-complete", discovered, processed, cached_count))
    return results
