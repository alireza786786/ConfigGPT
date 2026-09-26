# ConfigGPT — Phase 18 Implementation Plan

Status: PLAN ONLY — AWAITING APPROVAL

## Purpose

Phase 18 is an implementation phase for the already approved ConfigGPT architecture.

No implementation is authorized by this document alone.

All previously approved architecture, contracts, tests, security requirements, README content, branding, and hubcore behavior must be preserved.

The rule is:

> Add approved functionality without removing or weakening previously approved functionality.

---

## Q1 — Repository Baseline Audit

Before any implementation:

- Verify current branch is `main`.
- Verify current HEAD is `010e8cb`.
- Verify `origin/main` matches the local approved baseline.
- Run the complete existing test suite.
- Confirm `hubcore/` has no unexpected modifications.
- Inspect the current repository structure.
- Inspect existing output contracts and tests.
- Inspect `docs/ARCHITECTURE_v1.md`.
- Confirm no secret values are printed, committed, or introduced.

No source code changes are permitted during Q1.

---

## Q2 — Single Source of Truth Design

Review and prepare the implementation plan for:

`data/index.json`

The canonical index must be generated data, never manually edited.

It must be capable of representing, where available:

- pipeline run identifier
- generation timestamp
- tested count
- alive count
- published count
- countries
- protocols
- nodes
- origin/source identity
- protocol
- transport
- host
- port
- geographic metadata
- measured ping
- jitter
- architecture
- status
- rank
- stable line identity/hash
- deterministic grouping information

All public rendered artifacts must remain derivable from the canonical data source.

No implementation is authorized until the exact schema and compatibility impact are reviewed.

---

## Q3 — Statistics Contract

Prepare the implementation plan for:

`Statistics/status.txt`

The generated file must contain:

- Last update
- Tested count
- Alive count
- Published count
- Countries
- Protocols

The file must be regenerated deterministically on each pipeline run.

It must not contain secrets, source URLs, credentials, or fabricated measurements.

Existing output contracts must remain compatible.

---

## Q4 — Deterministic Output Integration

Prepare the implementation plan for integrating canonical data with the existing output system.

The implementation must preserve:

- protocol outputs
- transport outputs
- country outputs
- subscription outputs
- existing ordering rules
- CRLF/LF rules where already required
- exact ConfigGPT branding header
- fail-soft behavior
- no fabricated latency
- no fabricated jitter
- deterministic rendering
- path-safety rules
- existing tests and contracts

No existing approved output may be removed merely because a new canonical index is introduced.

---

## Q5 — Documentation / Dashboard Boundary

Review the future documentation/dashboard boundary.

Potential future components include:

- GitHub Pages source under `docs/`
- static consumption of `data/index.json`
- search
- filtering
- country/protocol/transport views
- Output Center

Phase 18 must NOT introduce:

- Telegram integration
- private collector code
- scheduler
- deployment system
- secrets
- bot tokens
- source URLs belonging to the private collector

Those remain outside the public repository boundary unless separately approved.

---

## Q6 — Verification and Approval Gate

Before implementation:

1. Produce the exact list of files that will change.
2. Produce the exact list of files that will remain untouched.
3. Define all new tests.
4. Define acceptance criteria.
5. Define rollback procedure.
6. Identify compatibility risks.
7. Run the existing test suite before implementation.
8. Do not commit or push without explicit approval.

Implementation is authorized only after human review and explicit approval of this Phase 18 plan.

---

## Protected Requirements

The following must not be removed or weakened:

- existing hubcore behavior
- existing parsing and normalization behavior
- deduplication
- validation
- latency rules
- ranking/scoring behavior
- security protections
- deterministic output rules
- fail-soft behavior
- existing tests
- README approved content
- banner
- Telegram QR asset
- architecture documentation
- secret-handling rules
- public/private repository separation

No requirement may be silently replaced by a new design.

---

## Implementation Rule

This document is a planning and approval gate only.

It does NOT authorize coding.

It does NOT authorize file modification.

It does NOT authorize commit.

It does NOT authorize push.

Any implementation must be performed only after explicit human approval.

---

## Final Status

PHASE 18: PLAN ONLY

Q1: NOT EXECUTED
Q2: NOT EXECUTED
Q3: NOT EXECUTED
Q4: NOT EXECUTED
Q5: NOT EXECUTED
Q6: NOT EXECUTED

STOP — WAIT FOR EXPLICIT APPROVAL.
