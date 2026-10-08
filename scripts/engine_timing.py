"""Run offline PipelineGuard engine timing breakdowns against a project."""
import argparse
from pathlib import Path
from statistics import median

from pipelineguard.engine import run_scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--profile", default="Standard")
    parser.add_argument("--summary", action="store_true", help="Print median/min/max per stage")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    samples = []
    for index in range(args.runs):
        timings = {}
        report = run_scan(args.path, online=False, profile=args.profile, timings=timings)
        print(f"RUN {index + 1} status={report['status']}")
        for stage, milliseconds in timings.items():
            print(f"  {stage:20s} {milliseconds:9.2f} ms")
        print(f"  secret_cache={report.get('secret_cache')}")
        samples.append(timings)
    if args.summary:
        print(f"SUMMARY ({len(samples)} runs; milliseconds)")
        for stage in samples[0]:
            values = [sample[stage] for sample in samples if stage in sample]
            if values:
                print(f"  {stage:20s} median={median(values):9.2f} min={min(values):9.2f} max={max(values):9.2f}")
    print("Offline benchmark: OSV network latency is not measured.")


if __name__ == "__main__":
    main()
