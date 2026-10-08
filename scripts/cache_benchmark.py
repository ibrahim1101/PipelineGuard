"""Measure cold and warm secret cache scans using temporary sample files."""
import tempfile
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
        with patch.dict("os.environ", {"LOCALAPPDATA": str(root / "cache")}):
            for phase in ("cold", "warm", "modified"):
                if phase == "modified":
                    (project / "sample_0.txt").write_text("changed data " * 300)
                metrics = {}
                scan_secrets_incremental(project, set(), 100000, metrics=metrics)
                print(phase, metrics)

if __name__ == "__main__":
    main()
