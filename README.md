# ConfigGPT

![Banner](docs/images/configgpt-banner.png)

Open Source Configuration Intelligence. A deterministic pipeline (hubcore) for proxy/config ingestion, dedup, scoring, ranking and artifact generation. Built for transparency — no secrets exposed, no fabricated latency, full audit trail.

---

## Resources

- **Global Configurations** — multi-source aggregated configs
- **All Protocols** — VMess, VLESS, Trojan, Shadowsocks, SOCKS

---

## Protocols

- VMess
- VLESS
- Trojan
- Shadowsocks
- SOCKS

---

## Transports

- WebSocket (WS)
- gRPC
- TCP
- HTTP/2
- QUIC

---

## Countries

- Germany
- Netherlands
- Finland
- USA
- More (see `docs/ARCHITECTURE_v1.md` for grouping logic)

---

## Output Formats

- Subscription links (`Subscription/plain/`, `Subscription/base64/`)
- Raw configurations (`Config/*.txt`, per protocol)
- Filtered lists (`transports/*.txt`, `Country/*.txt`)

---

## Telegram

Join updates and announcements:

- Channel: [Goodbaye_filtering](https://t.me/Goodbaye_filtering)
- Handle: `@Goodbaye_filtering`
- QR: `docs/images/telegram_qr.png` (points to `https://t.me/Goodbaye_filtering`)

---

## Architecture

Sources → Collector → Parser → Deduplication → Validation → Classification → Output

See full design: [`docs/ARCHITECTURE_v1.md`](docs/ARCHITECTURE_v1.md) (Phase 16 — Two-Layer architecture, Pipeline Flow, Single Source of Truth `data/index.json`, Quality Rules, QR Policy, Risk Register).

---

## Testing

```bash
pip install pytest
python -m pytest
```

Full suite: 881 items (current baseline: 876 passed, 8 skipped; Phase 17 adds 3 new tests in `tests/test_phase17_foundation.py`).

---

## Contribution

Pull requests welcome. Before submitting:
- Run `python -m pytest`
- Ensure no secrets in output or logs (`hubcore/` safety checks)
- Update `data/index.json` if schema changes are proposed

---

## Documentation

- [`docs/ARCHITECTURE_v1.md`](docs/ARCHITECTURE_v1.md) — canonical architecture design (Phase 14 pipeline orchestration, Phase 16 design)
- `README.md` — this file

---

## Limitations

- `.github/workflows/ci.yml` provides minimal pytest CI (pytest only); no deploy automation or Telegram integration in repository.
- `Config/*.txt` legacy files are optional; the migration integration test skips when absent (`tests/test_ingest.py`).
- No CLI, scheduler, or external service dependencies included in the public repository.
- `docs/images/` (banner, QR) reserved but not yet created — placeholder paths only.
- `gcm-diagnose.log` is a temporary diagnostic file (credential-manager output) — not part of the repository.

---

## Star / Support

If this project is useful, star [`https://github.com/alireza786786/ConfigGPT`](https://github.com/alireza786786/ConfigGPT) — it helps visibility and signals community interest for future Phase 18 work (GitHub Pages Dashboard, search, filter, static API endpoints).

---

## فارسی

ConfigGPT یک خط لوله (pipeline) متن‌باز برای بررسی، رتبه‌بندی و تولید خروجی کانفیگ‌های پروکسی است.

- مراحل اصلی: Source → Fetch → Parse → Dedup → TCP → Handshake → Real Ping → Score → Rank → Output
- بدون داده ساختگی (fabrication): هر مقدار از اندازه‌گیری واقعی (Phase 9) می‌آید.
- امنیت: هیچ credential در پیام خطا یا لاگ منتشر نمی‌شود (`hubcore/` contracts).
- خروجی‌ها: `Config/`, `Transport/`, `Country/`, `Subscription/` با Header دقیق (`👉🆔@Goodbaye_filtering📡...`).
- مستند معماری: [`docs/ARCHITECTURE_v1.md`](docs/ARCHITECTURE_v1.md)
- کانال تلگرام: [`@Goodbaye_filtering`](https://t.me/Goodbaye_filtering) — QR در `docs/images/telegram_qr.png`

---

*Status: README draft only. No file modified. No commit made. No push. Phase 18 not started.*