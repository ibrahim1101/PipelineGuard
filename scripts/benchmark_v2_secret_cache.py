"""Reproducible local benchmark for incremental secret scanning.

Run: python scripts/benchmark_v2_secret_cache.py --files 1000 --rounds 3
Creates only synthetic, non-sensitive data in a temporary directory.
"""
from __future__ import annotations

import argparse
import statistics
import tempfile
import time
from pathlib import Path

# Support direct execution from a repository checkout without installation.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipelineguard.secret_cache import scan_secrets_incremental
from scanners.secret_scanner import scan_directory


def measure(action, rounds: int) -> tuple[float, float]:
    timings = []
    for _ in range(rounds):
        start = time.perf_counter()
        action()
        timings.append(time.perf_counter() - start)
    return statistics.median(timings), min(timings)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.files <= 100_000 or not 1 <= args.rounds <= 20:
        parser.error("files must be 1..100000 and rounds 1..20")
    with tempfile.TemporaryDirectory(prefix="pipelineguard-bench-") as folder:
        root = Path(folder) / "repository"
        root.mkdir()
        for index in range(args.files):
            (root / f"file-{index:06d}.py").write_text(
                f"# synthetic source {index}\nmessage = 'hello world'\n",
                encoding="utf-8",
            )
        ignored: set[str] = set()
        limit = 1_000_000
        fresh = lambda: scan_directory(root, ignored, limit)
        incremental = lambda: scan_secrets_incremental(root, ignored, limit)
        baseline = fresh()
        first = incremental()
        reused = incremental()
        if baseline != first or baseline != reused:
            raise AssertionError("Cached findings differ from a full scan")
        cold_median, _ = measure(fresh, args.rounds)
        warm_median, _ = measure(incremental, args.rounds)
        print(f"Files: {args.files}; rounds: {args.rounds}")
        print(f"Fresh full-scan median: {cold_median:.4f}s")
        print(f"Warm cache median:      {warm_median:.4f}s")
        print(f"Speed ratio (fresh/warm): {cold_median / warm_median:.2f}x" if warm_median else "Warm scan too fast to measure")
        print("Parity: PASS")


if __name__ == "__main__":
    main()
