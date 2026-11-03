# Titan: Deterministic Governance Substrate & Runtime Kernel

![Status](https://img.shields.io/badge/Status-Constitutional_Hold-red?style=flat-square) ![Language](https://img.shields.io/badge/Language-Rust_2024-orange?style=flat-square) ![Architecture](https://img.shields.io/badge/Architecture-Actor_Model__SQLite-blue?style=flat-square) ![Standard](https://img.shields.io/badge/Standard-BUBBA_2.0-lightgrey?style=flat-square)

**Titan** is the top-level development governance constitution and mechanical governing substrate for the Aimcurio ecosystem. **Titan Forward** provides its bounded implementation kernel, enforcing fixture-only authority records, capability admission, immutable evidence chains, and atomic SQLite state transitions.

---

## Executive Overview

Titan guarantees architectural invariants, process integrity, and cryptographic evidence continuity across autonomous and human development lifecycles. Rather than relying on self-certified claims or discretionary prompts, Titan enforces mechanical state machine verification where every capability grant, code modification, and promotion requires falsifiable evidence and authenticated authority records.

---

## Architecture & Substrate Components

```
                   [ Titan Constitution 1.0.0 ]
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
 [Titan Forward Kernel]                     [RuleForge Companion (REQ-004)]
  • SQLite State Machine                     • Swappable Rule Engines
  • Fixture Admission Gates                  • 37 Atomicity Checks
  • Evidence Ledger Chaining                 • Oracle Verification CLI
```

- **Titan Constitution 1.0.0:** Ratified constitutional foundation (SHA-256: `af6e53c41cf519f4d202cccf63724c4e3de7b0df2888d0a8e6fd321874e25422`).
- **Titan Forward Kernel:** Rust 2024 library for actor-model isolation, authority record verification, and atomic database state progression.
- **RuleForge Engine (Companion CR-P007):** Verification and companion tooling providing atomicity and regression checking for requirement REQ-004.

---

## Current Status & Constitutional Hold Notice

> [!WARNING]
> **CONSTITUTIONAL HOLD NOTICE:** While companion tool integration tests succeed cleanly (37/37 checks PASS at commit `096f9dd`), Titan Forward's core kernel remains on **CONSTITUTIONAL HOLD**. Core kernel tests fail closed without authorized F02/F04/F05/F06 fixtures. Human constitutional authority ratification of evidence admission gate F06 and conservation tolerances is pending. No release qualification is claimed.

| Component | Status | Evidence Reference |
| :--- | :--- | :--- |
| **Titan Constitution** | **RATIFIED (v1.0.0)** | `TITAN_AUTHORITY_BASELINE.md` |
| **RuleForge Companion (REQ-004)** | **QUALIFIED (37/37 Checks PASS)** | `req004-atomicity.log` (commit `096f9dd`) |
| **Titan Forward Kernel** | **HOLD / BLOCKED ON ADMISSION GATE** | `kernel-tests.log` |
| **Release Qualification** | **UNQUALIFIED / NOT RELEASED** | Portfolio Register CR-001 |

---

## Build & Test Instructions

### Prerequisites
- Rust 2024 Nightly / Latest Stable
- SQLite 3.40+

### Testing Companion Engine
```powershell
# Build kernel library
cargo build --lib

# Run isolated companion checks (passes in authorized fixture environment)
cargo test --test companion_atomicity
```

---

## Governance & Provenance
Titan is the root of trust for Aimcurio system governance. Alterations to constitutional tolerances or evidence gates require cryptographic human authorization.
