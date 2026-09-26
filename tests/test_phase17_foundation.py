# Phase 17 Foundation Tests

import os
import json
import subprocess
import sys

def test_index_json_exists():
    assert os.path.isfile("data/index.json")
    with open("data/index.json") as f:
        data = json.load(f)
    assert data["version"] == 1
    assert "stats" in data
    assert "nodes" in data


def test_output_sample_runs():
    result = subprocess.run(
        [sys.executable, "collector/output_sample.py"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert os.path.isfile("output/sample.txt")
    with open("output/sample.txt", "rb") as f:
        content = f.read().decode("utf-8")
    assert "Goodbaye_filtering" in content
    # Legacy contract: CRLF separator with trailing newline
    assert b"\r\n" in content.encode("utf-8")


def test_stats_writer_runs():
    result = subprocess.run(
        [sys.executable, "collector/stats_writer.py"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert os.path.isfile("output/status.txt")
    with open("output/status.txt") as f:
        content = f.read()
    assert "Last update:" in content
    assert "Tested count:" in content
