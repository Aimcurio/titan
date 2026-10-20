# Titan Forward

Titan Forward is a Rust library for fixture-only authority records, admission, bounded capabilities, evidence/recovery, verification/eligibility, and an atomic SQLite transition. This is the **original fixture development baseline**, not a production system.

This branch preserves the existing canonical Titan Forward source at `08328274bed440e8ba0c1747a9984bab21c1a740`. The older Projects mirror ends at F06; F07 already exists in this source history. Publication does not independently qualify or accept F07.

## Current development record

**Titan is under construction and NOT RELEASE QUALIFIED.** Start with [current status](STATUS.md) for the open Q01–Q08 findings and next work, [development history](DEVELOPMENT_HISTORY.md) for saved milestones and blocked attempts, and [the original October 20 audit and evidence](docs/history/2026-10-20/README.md) for the detailed qualification record.

This default branch preserves the earlier baseline source. The newer implementation candidate is on [`completion/20261018`](https://github.com/Aimcurio/titan/tree/completion/20261018); its original published commit remains `2be4dfb9b51e1d88c6d0e5f603838d5bed3abfa5`. The documentation update does not merge that implementation into this branch. See [how development changes are saved and undone](docs/HISTORY_WORKFLOW.md).

## Build and test

Use Rust 1.97.1 (selected by `rust-toolchain.toml`) and a working native C compiler for bundled SQLite. On Windows, use a Rust/MSVC development shell with the Visual Studio C++ tools available. Dependencies are pinned in `Cargo.lock`.

```powershell
rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt
cargo build --locked
cargo test --locked --no-fail-fast
```

Use `--offline` only when the exact locked dependencies are cached. The original baseline contains historical absolute fixture roots and is not independently verified on a clean machine. Tests at that revision can require the original fixture prerequisites. The completion branch replaces those fixture roots with build-local directories, but retains the release blockers below.

The companion scripts `tools/verify_all.py` and `tools/tool_flight.py` on `completion/20261018` assume the preserved campaign layout: `repos/<component>`, external `build`, `tmp`, and `evidence` directories, and installed SPC Node dependencies. They are not standalone commands for a fresh Titan-only clone. Flight execution also assumes Windows executable names and built Rust tool binaries.

## Qualification and authority

**NOT RELEASE QUALIFIED.** The original [October 20 independent qualification report](docs/history/2026-10-20/Titan_Independent_Qualification_Report.md) records confirmed hard-link acceptance, recorder evidence loss, and descendant containment failures, plus unresolved provenance, coverage, repeatability, formatting and platform gates. A subsequent remediation attempt was blocked by its runtime and produced no fixes. The earlier ledger's 281 passes and four Windows setup failures are historical implementation results, not the latest acceptance conclusion. Full five-tool integration remains blocked by Learning Trace's learner-assessment role mismatch; browser verification, F08, and operational Root remain separately gated. See [STATUS.md](STATUS.md) for the current development record.

Phase-1 is a separate architecture package with `implementation_authorized:false`; it is not included here. Fixture authority does not confer operational authority. Publishing this source authorizes no production release, enrollment, deployment, candidate promotion, or Phase-1 activation.

See [PUBLICATION_STATUS.md](PUBLICATION_STATUS.md) for source identity, history handling, and companion boundaries.
