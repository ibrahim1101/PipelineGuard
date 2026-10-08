"""Reproducible local benchmark for incremental secret scanning.

Run: python scripts/benchmark_v2_secret_cache.py --files 1000 --rounds 3
Creates only synthetic, non-sensitive data in a temporary directory.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import statistics
import tempfile
import time
from pathlib import Path

# Support direct execution from a repository checkout without installation.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipelineguard.secret_cache import scan_secrets_incremental, choose_scan_strategy
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
    parser.add_argument("--lines", type=int, default=2, help="Synthetic lines per file (2..500)")
    args = parser.parse_args()
    if not 1 <= args.files <= 100_000 or not 1 <= args.rounds <= 20 or not 2 <= args.lines <= 500:
        parser.error("files must be 1..100000 and rounds 1..20")
    with tempfile.TemporaryDirectory(prefix="pipelineguard-bench-") as folder:
        root = Path(folder) / "repository"
        root.mkdir()
        for index in range(args.files):
            (root / f"file-{index:06d}.py").write_text(
                f"# synthetic source {index}\nmessage = 'hello world'\n",
                encoding="utf-8",
            )
        if args.lines > 2:
            for index in range(args.files):
                (root / f"file-{index:06d}.py").write_text(
                    f"# synthetic source {index}\n" + "message = 'hello world'\n" * (args.lines - 1),
                    encoding="utf-8",
                )
        cache_home = Path(folder) / "cache"
        os.environ["LOCALAPPDATA"] = str(cache_home)
        os.environ["XDG_CACHE_HOME"] = str(cache_home)
        cache_file = cache_home / "PipelineGuard" / "secret-findings" / (hashlib.sha256(os.fsencode(str(root.resolve()))).hexdigest() + ".json")
        ignored: set[str] = set()
        limit = 1_000_000
        fresh = lambda: scan_directory(root, ignored, limit)
        incremental = lambda: scan_secrets_incremental(root, ignored, limit)
        adaptive = lambda: (fresh() if choose_scan_strategy(root, ignored, limit) == "full" else incremental())
        strategy = choose_scan_strategy(root, ignored, limit)
        baseline = fresh()
        first = incremental()
        reused = incremental()
        if baseline != first or baseline != reused or baseline != adaptive():
            raise AssertionError("Cached findings differ from a full scan")
        cold_median, _ = measure(fresh, args.rounds)
        warm_median, _ = measure(incremental, args.rounds)
        adaptive_median, _ = measure(adaptive, args.rounds)
        def cold_incremental():
            cache_file.unlink(missing_ok=True)
            return incremental()
        cold_cache_median, _ = measure(cold_incremental, args.rounds)
        incremental()
        changed = root / "file-000000.py"
        def modified_incremental():
            content = changed.read_text(encoding="utf-8")
            content = content.replace("hello world", "hello there") if "hello world" in content else content.replace("hello there", "hello world")
            changed.write_text(content, encoding="utf-8")
            return incremental()
        modified_median, _ = measure(modified_incremental, args.rounds)
        if fresh() != incremental():
            raise AssertionError("Modified-file findings differ from full scan")
        print(f"Files: {args.files}; lines/file: {args.lines}; rounds: {args.rounds}")
        print(f"Adaptive strategy: {strategy}")
        print(f"Fresh full-scan median: {cold_median:.4f}s")
        print(f"Warm cache median:      {warm_median:.4f}s")
        print(f"Speed ratio (fresh/warm): {cold_median / warm_median:.2f}x" if warm_median else "Warm scan too fast to measure")
        print(f"Adaptive median:       {adaptive_median:.4f}s")
        print(f"Cold cache median:     {cold_cache_median:.4f}s")
        print(f"Modified cache median: {modified_median:.4f}s")
        print(f"Adaptive ratio:        {cold_median / adaptive_median:.2f}x" if adaptive_median else "Adaptive too fast to measure")
        print("Parity: PASS")


if __name__ == "__main__":
    main()
