"""Time read-only Git operations without printing repository metadata."""
import argparse
import subprocess
from pathlib import Path
from statistics import median
from time import perf_counter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be positive")
    for label, command in [("commit", ["rev-parse", "HEAD"]), ("branch", ["branch", "--show-current"]), ("status", ["status", "--porcelain"]), ("remote", ["config", "--get", "remote.origin.url"])]:
        samples = []
        failures = 0
        for _ in range(args.runs):
            start = perf_counter()
            try:
                result = subprocess.run(["git", "-C", str(Path.cwd()), *command], capture_output=True, timeout=5)
                failures += result.returncode != 0
            except (OSError, subprocess.SubprocessError):
                failures += 1
            samples.append((perf_counter() - start) * 1000)
        print(f"{label}: median={median(samples):.2f} ms; min={min(samples):.2f}; max={max(samples):.2f}; failures={failures}")
    print("Output is suppressed to protect remote credentials.")


if __name__ == "__main__":
    main()
