# ConfigGPT Architecture v1.0 — Design Document (AUDIT ONLY, Phase 16)

Status: DESIGN / AUDIT ONLY. No source code changed. No commit made for this file.

---

## 1. Two-Layer Architecture

Public Repository (hubcore engine):
- hubcore/
  - parser (parsing/)
  - normalize (model, identity)
  - dedup (dedup)
  - validation (tcpval, handshake)
  - geo (geo, resolver)
  - latency (latency, measure)
  - ranking (ranking, scoring)
  - output generator (output, writer)
- tests/
- .github/workflows/
- docs/ (future: GitHub Pages Dashboard)
- README.md, pyproject.toml

Private Collector (separate repo or protected branch; not in this repo):
- sources/ (guard1..guard8 configurations, not committed here)
- scheduler/ (cron or task runner)
- telegram_publisher/ (message formatter + bot token)
- secrets/ (.env, tokens — NEVER committed; excluded by .gitignore)

Separation reason: public repo must never contain secrets, source URLs, or collector schedules.

---

## 2. Final Pipeline Flow

Source -> Fetch -> Parse -> Normalize -> Dedup -> TCP validation -> Handshake -> Real Ping -> Quality selection -> Output generation -> GitHub files -> Telegram output

Stage mapping to hubcore modules:
- Source / Fetch: fetch.py, ingest.py
- Parse / Normalize: parsing/, model.py, identity.py
- Dedup: dedup.py
- TCP validation: tcpval.py
- Handshake: handshake.py
- Real Ping: measure.py, latency.py
- Quality selection: scoring.py, ranking.py
- Output generation: output.py
- GitHub files: writer.py (writes relative paths only; no deploy logic)
- Telegram output: external consumer (not in this repo)

---

## 3. Source Scheduler Design (Sequential Guards)

- guard1 .. guard8 executed sequentially, never in parallel.
- Each guard has a per-link timeout (default: 10s fetch + 5s TCP).
- Failure of one link logs a short reason code (e.g. "timeout", "refused", "dns_no_resolver") and continues to next link.
- The pipeline never aborts because of a single bad source; the audit trail records every failure.
- If all guards fail, the output is an empty valid artifact (legacy contract: 2-byte CRLF file) and status reports zero alive nodes.

---

## 4. Output Contract (Brand Header)

Every emitted config line MUST include the header exactly in this form:

👉🆔@Goodbaye_filtering📡[FLAG]®️[COUNTRY]©️[CITY]🅿️ping:[PING]ms~±[JITTER]ms⚡️[ARCHITECTURE]

Without this header, the output is invalid and must be rejected by output validation (UnsafeOutputTextError if any control character is injected).

Legacy rules preserved:
- Plain text: CRLF separator, one trailing CRLF.
- Base64 payload: LF-joined, no trailing LF.
- Group files are stable filters of global order, never re-sorted.

---

## 5. GitHub Output Structure

Country/
  - {sanitized_country_name}.txt  (groups by geo country)

Protocol/
  - vless.txt
  - vmess.txt
  - ss.txt (shadowsocks)
  - trojan.txt
  - hysteria2.txt
  - socks.txt
  - other.txt

Transport/
  - tcp.txt
  - ws.txt
  - grpc.txt
  - xhttp.txt
  - reality.txt  (future; keep slot reserved)

Subscription/
  - plain/guard{N}.txt
  - base64/guard{N}.txt
  - ultra_fast.txt (ping <= 200ms tier)
  - good_ping.txt (ping <= 500ms tier)

README.md must be present in root and in Config/.

---

## 6. QR Policy

- QR codes are produced at file-level and section-level only.
- Per-config QR is explicitly NOT produced (would expose individual nodes and bloat output).
- QR payload points to a stable index file (data/index.json) or to the repository URL, never to a live node directly.

---

## 7. Quality Rules (No Quantity Guarantee)

Published configs must satisfy:
- Real measured latency (MEASURED kind, not TCP_CONNECT or fabricated)
- Positive ping (< 0 rejected; NaN/inf rejected)
- Jitter present (if missing -> unranked; never fabricated)
- TCP success + handshake success (fail-soft removes bad nodes)
- Freshness: source ingested within scheduled window
- Stability: node must respond to at least one full probe cycle
- Quality score: calculated by scoring.py; ranked by ranking.py
- Only ranked nodes appear in Protocol/Transport/Subscription files; unranked nodes are audit-only.

---

## 8. Single Source of Truth: data/index.json

Design: one canonical JSON file (generated, never edited by hand) that drives all outputs.

Schema proposal:
{
  "version": 1,
  "generated_at": "ISO8601",
  "pipeline_run_id": "sha",
  "stats": {
    "last_update": "...",
    "tested": 120,
    "alive": 87,
    "published": 87,
    "countries": ["CA", "DE", ...],
    "protocols": ["VLESS", "VMESS", ...]
  },
  "nodes": [
    {
      "origin": "guard1",
      "line_no": 3,
      "protocol": "VLESS",
      "transport": "TCP",
      "host": "...",
      "port": 443,
      "geo": {"country": "Canada", "city": "Toronto", "code": "CA"},
      "ping_ms": 42.5,
      "jitter_ms": 3.2,
      "arch": "x86_64",
      "status": "ok",
      "rank": 1,
      "line_hash": "..."
    }
  ],
  "groups": {
    "country": {...},
    "protocol": {...},
    "transport": {...},
    "ping_tier": {"ultra_fast": [...], "good": [...]}
  }
}

All artifacts (text files, base64 files, country/protocol/transport groups) are derived from this JSON by deterministic render functions in output.py.

---

## 9. Statistics File: Statistics/status.txt

Mandatory fields (one per line, key: value):
- Last update: {timestamp}
- Tested count: {N}
- Alive count: {N}
- Published count: {N}
- Countries: {count} ({list})
- Protocols: {count} ({list})

This file is regenerated on every pipeline run; it never accumulates historical data (history lives in data/index.json if needed).

---

## 10. Future-Proofing (Reserved in Architecture)

Slots reserved but NOT implemented in Phase 15:
- docs/ — GitHub Pages source; static site generator input.
- Search — index.json can be consumed by a static search page (no server needed).
- Filter — filter parameters encoded in query strings against index.json groups.
- API endpoints — future endpoint can serve index.json or rendered artifacts; design must keep paths relative and deterministic so an API wrapper is only a thin layer.

No Telegram integration, no scheduler, no deploy, and no CLI are added in this architecture document. Those belong to the Private Collector layer.

---

## Risk Register (Phase 16 Design Only)

1. Secret leakage in output — MITIGATED: output.py refuses control characters; pipeline audit reasons never include URLs or credentials.
2. Fabricated latency — MITIGATED: measure.py never invents values; missing jitter -> unranked; missing ping -> omitted (default) or sentinel (explicit policy only).
3. Path traversal in writer — MITIGATED: writer validates relative paths; absolute paths rejected; MAX_RELATIVE_PATH enforced.
4. Non-deterministic ranking — MITIGATED: ranking uses fixed ORDER_SCORE_DESC and deterministic tie-break; no entropy sources used.
5. Legacy migration errors — MITIGATED: test skips when Config/*.txt missing; no forced migration.
6. CI failure masking bugs — MITIGATED: CI runs full pytest suite; failure reported explicitly; no silent suppression.
7. Dependency drift — MITIGATED: pyproject.toml pins stdlib-only runtime; pytest for dev only; no external runtime packages.

---

## Improvement Proposals (Post-Phase 16, Not Executed)

- Add `docs/` folder with GitHub Pages config (`_config.yml`, index template).
- Generate `data/index.json` in writer phase (add `plan_outputs` hook in writer.py).
- Add `Statistics/status.txt` renderer in output.py (new method; no behavior change to existing artifacts).
- Add `.gitignore` rule for `Config/*.txt` if legacy files are optional.
- Consider a static site generator (e.g. Jekyll or plain HTML from index.json) under `docs/`.

---

## Verification Checklist (Before Any Implementation)

- [x] No `hubcore/` file modified in Phase 16.
- [x] No source code created or deleted.
- [x] No commit made for this design document (only documented here).
- [x] No new runtime dependencies proposed.
- [x] No Telegram, deploy, or QR logic added to source.
- [x] Pipeline contract preserved (fail-soft, no fabrication, audit trail).
- [x] Output header format preserved exactly.
- [x] Single Source of Truth (`data/index.json`) defined but not implemented.

---

Status: AUDIT + DESIGN COMPLETE. STOP. Wait for approval before any implementation.
