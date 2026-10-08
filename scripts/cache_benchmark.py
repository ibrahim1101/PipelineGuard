"""Repeatable synthetic secret-cache benchmark with median timings."""
import argparse
import statistics
import tempfile
from pathlib import Path
from time import perf_counter
from unittest.mock import patch

from pipelineguard.secret_cache import scan_secrets_incremental


def run_case(file_count: int, repetitions: int) -> None:
    samples = {"cold": [], "warm": [], "modified": []}
    for trial in range(repetitions):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            project = root / "sample"
            project.mkdir()
            for index in range(file_count):
                (project / f"sample_{index}.txt").write_text("sample data " * 300)
            with patch.dict("os.environ", {"LOCALAPPDATA": str(root / "cache")}):
                for phase in ("cold", "warm", "modified"):
                    if phase == "modified":
                        (project / "sample_0.txt").write_text("changed data " * 300)
                    metrics = {}
                    start = perf_counter()
                    scan_secrets_incremental(project, set(), 100000, metrics=metrics)
                    elapsed = (perf_counter() - start) * 1000
                    samples[phase].append(elapsed)
                    print(f"files={file_count} trial={trial + 1} {phase} {metrics} elapsed_ms={elapsed:.2f}")
                    expected_scanned = {"cold": file_count, "warm": 0, "modified": 1}[phase]
                    expected_reused = {"cold": 0, "warm": file_count, "modified": file_count - 1}[phase]
                    if metrics["scanned"] != expected_scanned or metrics["reused"] != expected_reused:
                        raise RuntimeError(f"Cache correctness check failed for {phase}: {metrics}")
    cold = statistics.median(samples["cold"])
    warm = statistics.median(samples["warm"])
    modified = statistics.median(samples["modified"])
    print(f"SUMMARY files={file_count} trials={repetitions} median_cold_ms={cold:.2f} "
          f"median_warm_ms={warm:.2f} median_modified_ms={modified:.2f} "
          f"median_cold_to_warm_ratio={cold / warm:.2f}x" if warm > 0 else
          f"SUMMARY files={file_count} warm timing below clock resolution")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, nargs="+", default=[40, 400],
                        help="Synthetic file counts to benchmark (default: 40 400)")
    parser.add_argument("--trials", type=int, default=5,
                        help="Independent cold/warm/modified trials per size (default: 5)")
    args = parser.parse_args()
    if args.trials < 1 or any(n < 1 or n > 10000 for n in args.files):
        parser.error("trials must be positive and file counts must be between 1 and 10000")
    for count in args.files:
        run_case(count, args.trials)


if __name__ == "__main__":
    main()
