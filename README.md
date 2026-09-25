# ConfigGPT

Configuration pipeline (hubcore) for proxy/config ingestion, dedup, scoring, ranking and deterministic output. Phases 1–14.

## Project goal

Audit, rank, and render proxy/config links with deterministic output. No secrets are exposed in errors or logs.

## Architecture

- `hubcore/` — core modules (ingest, dedup, parsing, geo, tcp, handshake, measure, score, rank, output, writer)
- `tests/` — pytest suite (881 tests)
- `hubcore/pipeline.py` — end-to-end pipeline orchestrator (Phase 14)

## Pipeline stages

1. Ingest  2. Dedup  3. DNS  4. Geo  5. TCP  6. Handshake  7. Measure  8. Score  9. Rank  10. Output  11. Writer

## Installation

No external runtime dependencies (stdlib only). For tests:

```bash
pip install pytest
```

## Running tests

```bash
python -m pytest
```

## Running locally

```python
from hubcore import run_pipeline, PipelineConfig, PipelineSource
```

## Status

- Repository: `main` @ `70ac6d8` (`Add hubcore package and test suite`)
- Working tree: clean
- Tests: 873 passed, 7 skipped, 1 failed (`test_ingest_real_config_files` fails when optional `Config/*.txt` legacy files are missing — fixed by skip condition)
- `.github/workflows/`: added in Phase 15 (`ci.yml`)
- `README.md`: completed in Phase 15

## Limitations

- `.github/workflows/` is minimal (pytest only); no deploy or Telegram integration.
- Optional legacy `Config/*.txt` files are not included; the migration integration test skips when absent.
- No CLI, scheduler, or external service dependencies.
