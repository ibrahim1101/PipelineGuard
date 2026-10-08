"""Measure cold and warm secret cache scans using temporary sample files."""
import tempfile
from time import perf_counter
from pathlib import Path
from unittest.mock import patch
from pipelineguard.secret_cache import scan_secrets_incremental

def main():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        project = root / "sample"
        project.mkdir()
        for index in range(40):
            (project / f"sample_{index}.txt").write_text("sample data " * 300)
        durations = {}
        with patch.dict("os.environ", {"LOCALAPPDATA": str(root / "cache")}):
            for phase in ("cold", "warm", "modified"):
                if phase == "modified":
                    (project / "sample_0.txt").write_text("changed data " * 300)
                metrics = {}
                started = perf_counter()
                scan_secrets_incremental(project, set(), 100000, metrics=metrics)
                durations[phase] = perf_counter() - started
                print(phase, metrics, f"elapsed_ms={durations[phase] * 1000:.2f}")
        if durations["warm"] > 0:
            print(f"cold_to_warm_ratio={durations['cold'] / durations['warm']:.2f}x")
        print("Timing is illustrative, not a reliable performance claim; repeat on larger workloads.")

if __name__ == "__main__":
    main()
