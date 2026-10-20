# Titan Forward

Titan Forward is a Rust library for fixture-only authority records, admission, bounded capabilities, evidence/recovery, verification/eligibility, and an atomic SQLite transition. This is the **completion candidate**, not a production system.

This branch adds build-local disposable fixture roots, isolated regression checks, and companion verification scripts. The underlying source candidate is `d58621eadde67e4164524586e07fc0cbb16a0fdd`.

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

**NOT RELEASE QUALIFIED.** The October 20 completion ledger records 281 Titan tests passed and four Windows link/junction setup failures. Those are prior implementation-agent results, not a new acceptance run for this publication. Independent qualification, portable installation, browser behavior, authenticated provenance, concurrent filesystem protection, complete process-tree containment, and full five-tool integration remain unverified or blocked. Learning Trace currently assesses learners and does not implement a software-decision journal. F08 and operational Root work remain separately gated.

Phase-1 is a separate architecture package with `implementation_authorized:false`; it is not included here. Fixture authority does not confer operational authority. Publishing this source authorizes no production release, enrollment, deployment, candidate promotion, or Phase-1 activation.

See [PUBLICATION_STATUS.md](PUBLICATION_STATUS.md) for source identity, history handling, and companion boundaries.
