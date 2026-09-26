#!/usr/bin/env python3
"""Phase 17 Foundation: Statistics writer (reads data/index.json)."""
import json
from datetime import datetime


def generate_stats(index_path: str = "data/index.json", out_path: str = "output/status.txt"):
    with open(index_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    stats = data.get("stats", {})
    content = (
        f"Last update: {stats.get('last_update', 'unknown')}\n"
        f"Tested count: {stats.get('tested', 0)}\n"
        f"Alive count: {stats.get('alive', 0)}\n"
        f"Published count: {stats.get('published', 0)}\n"
        f"Countries: {len(stats.get('countries', []))} ({', '.join(stats.get('countries', []))})\n"
        f"Protocols: {len(stats.get('protocols', []))} ({', '.join(stats.get('protocols', []))})\n"
    )
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    return out_path


if __name__ == "__main__":
    path = generate_stats()
    print(f"Generated: {path}")
