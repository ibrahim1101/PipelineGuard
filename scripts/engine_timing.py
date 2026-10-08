"""Run offline PipelineGuard engine timing breakdowns against a project."""
import argparse
from pathlib import Path

from pipelineguard.engine import run_scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--profile", default="Standard")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    for index in range(args.runs):
        timings = {}
        report = run_scan(args.path, online=False, profile=args.profile, timings=timings)
        print(f"RUN {index + 1} status={report['status']}")
        for stage, milliseconds in timings.items():
            print(f"  {stage:20s} {milliseconds:9.2f} ms")
        print(f"  secret_cache={report.get('secret_cache')}")
    print("Offline benchmark: OSV network latency is not measured.")


if __name__ == "__main__":
    main()
