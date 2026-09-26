#!/usr/bin/env python3
"""Phase 17 Foundation: Sample output generator (reads data/index.json)."""
import json

HEADER_TEMPLATE = (
    "👉🆔@Goodbaye_filtering"
    "📡{flag}®️{country}©️{city}"
    "🅿️ping:{ping}ms~±{jitter}ms"
    "⚡️{arch}\n"
)


def generate_sample_text(index_path: str = "data/index.json", out_path: str = "output/sample.txt"):
    with open(index_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    lines = []
    for node in data.get("nodes", []):
        if node.get("status") != "ok":
            continue
        header = HEADER_TEMPLATE.format(
            flag=node.get("geo", {}).get("code", "🌐"),
            country=node.get("geo", {}).get("country", "Unknown"),
            city=node.get("geo", {}).get("city", "Unknown"),
            ping=f"{node.get('ping_ms', 0):.1f}",
            jitter=f"{node.get('jitter_ms', 0):.1f}",
            arch=node.get("arch", "unknown"),
        )
        # Simulate a config body (not a real link; design only)
        lines.append(f"vless://{node['line_hash']}@{node['host']}:{node['port']}?security=tls&type=tcp#{header}")
    content = "\r\n".join(lines) + "\r\n"
    with open(out_path, "wb") as f:
        f.write(content.encode("utf-8"))
    return out_path, len(lines)


if __name__ == "__main__":
    path, count = generate_sample_text()
    print(f"Generated: {path} ({count} lines)")
