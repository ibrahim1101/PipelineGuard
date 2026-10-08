from pipelineguard.cache import ScanCache
from pipelineguard.orchestrator import fingerprint_files


def test_worker_queue_does_not_eagerly_consume_file_generator(tmp_path):
    for i in range(40):
        (tmp_path / f"{i}.txt").write_text(f"{i}")
    consumed = 0
    seen_at_first_result = []

    def source():
        nonlocal consumed
        for i in range(40):
            consumed += 1
            yield tmp_path / f"{i}.txt"

    def on_progress(event):
        if event.processed == 1 and not seen_at_first_result:
            seen_at_first_result.append(consumed)

    cache = ScanCache.load(tmp_path)
    result = fingerprint_files(tmp_path, source(), cache, workers=2, progress=on_progress)
    assert len(result) == 40
    assert seen_at_first_result and seen_at_first_result[0] <= 4
