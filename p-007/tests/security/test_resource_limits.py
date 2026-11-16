import sys
from p007.models import Limits
from p007.runners import execute


def test_large_stdout_stopped_at_budget(tmp_path):
    code, output, error = execute(
        [sys.executable, "-c", "import os; os.write(1,b'x'*200000)"], tmp_path, Limits(output_bytes=1024)
    )
    assert error in ("resource", "invalid") and len(output) <= 1024


def test_process_memory_ceiling(tmp_path):
    code, output, error = execute(
        [sys.executable, "-c", "import time; x=bytearray(400*1024*1024); time.sleep(5)"],
        tmp_path,
        Limits(memory_mb=256, timeout_seconds=10),
    )
    assert code is None and error == "resource" and b"MEMORY" in output
