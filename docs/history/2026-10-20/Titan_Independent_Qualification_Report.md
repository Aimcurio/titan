# BUBBA — Titan independent qualification

**Stage: PUBLICATION VERIFIED → QUALIFICATION AUDIT COMPLETE → REMEDIATION REQUIRED.**

**Verdict: NOT RELEASE QUALIFIED.** Publication identity passes. The completion candidate fails independent qualification. Individual passing suites and a successful partial companion exchange do not clear the confirmed defects or authorize promotion.

Assessment date: October 20, 2026. Role: independent adversarial verifier. Workflow: one agent. No implementation changes, assertion changes, commits, pushes, merges, tags, releases, enrollment, Phase-1 activation, or operational Root actions occurred.

## In simple terms

The correct Titan source is published and its history is intact. Several tools work within their stated scope. Independent execution also exposed failures that the earlier Windows setup restrictions had prevented from being exercised. Most seriously, F04 accepts hard-linked evidence on Linux, and the recorder can lose a successfully captured artifact while still exporting a clean result. Evidence Forge detects an inherited-pipe problem but leaves a descendant able to keep writing after verification returns.

This report qualifies only observed claims. It does not accept Titan as a complete operational system.

## Identity and evidence basis

Remote repository: [Aimcurio/titan](https://github.com/Aimcurio/titan), repository ID **1396000355**, default branch `main`.

| Ref / source | Exact commit | Exact tree |
|---|---|---|
| Published main | `4b34cc8b59810e892208eb3372763b299008e6bf` | `c6674274e7e7032ace3374fded75fa85b16e0642` |
| Published completion/20261018 | `2be4dfb9b51e1d88c6d0e5f603838d5bed3abfa5` | `33b390290c9031a66d7a4569767d92c1ac46507c` |
| Completion source parent | `d58621eadde67e4164524586e07fc0cbb16a0fdd` | `177081bfe5ab44c1c3d5488e089cf1df0f3e90ad` |
| Baseline source parent | `08328274bed440e8ba0c1747a9984bab21c1a740` | `5b65f4f25345180f2f435c96e995473e745a2eec` |

`git ls-remote`, local Git object inspection, and `git fsck --full --strict` independently confirm the recorded refs, trees and ancestry. Each publication tip adds only README.md and PUBLICATION_STATUS.md to its recorded source parent. Completion source directly descends from the baseline source; the baseline retains F06 parent `6843addb00da0e87bddd40b8de6570fd16a99ca3`. Main does not contain the completion implementation. See `evidence/publication-identity.log`.

All five separate companion bundles were cloned, checked out, and validated with Git. Their commits and trees exactly match `source-revisions.json` and the published companion table:

| Component | Exact commit | Exact tree |
|---|---|---|
| SPC / spc-remediation | `bf49ca990ffcbd89ff2d95b4b92369ab041ca8b3` | `061debc49e3795b6a8a44091c41872a66ba5b21a` |
| RuleForge | `537689eadacbfe6ec0e6821d140102371f63d5bc` | `021f834ae1563576da3a51a8f81c6cac5d46310e` |
| Evidence Forge | `6db96efc919bf82d8c449d22856497b132759827` | `314e76d8529b02e9297b1749debacb0408c865f4` |
| Learning Trace | `fbd7ee6cc1e1e0217879ffe6df808f2c3374b3e0` | `84018eec16714733423b8266d1bc5d1738a51758` |
| Flight Recorder | `8bae95274141bc94681b8675d41d049163b040ec` | `260e80823c907da1e19cdc270b611eeb227c122b` |

All six verification checkouts were clean at final inspection. `evidence/final-identities.json` records their identities and status; `evidence/tested-source-sha256.json` binds all 347 tracked files in those checkouts. Companion histories remain separate.

Inputs: updated `Titan_Publication_Resume_Report.md` (modified 2026-10-20T09:56:42Z), October 20 `TITAN_COMPLETION_LEDGER.md`, and `Titan-companion-candidates-and-verification.zip`. Input file identities are recorded in `evidence/input-record-identities.json`.

## Independent execution results

Environment: Linux x86_64, Rust **1.97.1**, Node **24.19.0**, npm **11.9.0**, Python **3.12.14**. This is not the original Windows/MSVC, Node 22, Python 3.13 environment. Rust dependencies were fetched with locked manifests, then tests ran offline. The exact Rust compiler identity is retained in `evidence/environment-identity.json`.

| Check | Independent result | Qualification meaning |
|---|---|---|
| Titan first full run | **FAIL: 283 passed / 2 failed**, exit 101 | F04 hard-link assertion and one F06 inventory assertion fail |
| Original aggregate script | **FAIL**, exit 1 | Titan 265/20 on retained fixtures; SPC/RuleForge CLI IPC blocked; EF fails; LT/FR pass |
| SPC selected suites | **PASS: 90 checks** | 80 existing checks + 10 completion regressions, using tsx module loader |
| RuleForge selected suites | **PASS: 57 checks** | 40 existing checks + 17 completion regressions, using same loader |
| Evidence Forge full suite | **FAIL: 56 passed / 12 failed**, exit 101 | Windows `cmd`/PowerShell assumptions prevent equivalent Linux execution; not twelve independently established product defects |
| Learning Trace | **PASS: 26 tests**, exit 0 | Learner-assessment scope only; synthetic fixtures do not establish human learning efficacy |
| Flight Recorder | **PASS: 22 tests**, exit 0 | Existing suite passes; independent stale-registry probe still demonstrates data loss |
| Titan formatting | **FAIL**, exit 1 | `cargo fmt --all -- --check` |
| Titan strict Clippy | **FAIL**, exit 101 | Six Unix `unused_mut` errors with `-D warnings` |
| Original tool flight | **BLOCKED**, script exit 1 | SPC tsx CLI cannot bind its IPC pipe: EPERM |
| Independent bounded exchange | **PASS: 13 observed commands** | Actual SPC → Oracle under EF → FR exchange, replay/resume, corruption rejection and conservative export |

The Node loader invocation was `node --import <SPC>/node_modules/tsx/dist/loader.mjs ...`. It runs the existing assertions without using the tsx CLI's IPC server. No permission was escalated and no test assertion was changed. These are separately labeled results, not a green result for the original aggregate entry point.

The bounded exchange uses native Linux binary paths and the Node module loader. Its exact argv/cwd/exits and stdout/stderr are in `evidence/independent-bounded-flight/`. It executed the real RuleForge candidate at `537689e...`, checked its revision-bound preparer contract, executed transitions, verified the package, replayed and resumed, rejected deliberate evidence corruption, and exported `completed_with_defects` with `release_promotion_authorized:false`. This is independent execution of a self-audit target; it is not an unrelated external-target qualification or live Titan orchestration.

`evidence/commands-and-outcomes.md` maps commands to raw files. Focused diagnostic runs never replace the failed full gate.

## Prioritized findings and required remediation

### Q01 — High — FAIL: F04 accepts a hard-linked evidence file on Linux

Source: published candidate `src/evidence.rs:181–237`, particularly link-count checks at 202–207 and 230–233, both compiled only on Windows. Existing `tests/a04.rs:1278–1288` creates a real hard link and requires rejection.

Observed: hard-link creation succeeds, then the rejection assertion fails at line 1288. This fails in the first full suite and again in a fresh, dedicated build target running that exact test. `evidence/f04-hardlink-confirmation.log` records **0 passed / 1 failed**, exit 101. This is an implementation defect on Linux, not the historical Windows setup-denial condition.

Remediation: enforce an ordinary single-link file identity through the opened file handle on every supported platform; fail closed if identity cannot be established. Preserve before/after identity and confinement checks. Retain this assertion and add outside-root aliases plus replacement/race cases. Verify both Linux and permitted Windows link setup. If Linux is unsupported, fail closed there and document that limitation rather than silently accepting aliases.

### Q02 — High — FAIL: stale recorder registries lose evidence and still export clean

Source: Flight Recorder `src/artifact.rs:95–147,225–259`. Registration appends to the caller's in-memory registry, then replaces `artifacts.json`; it does not reload/merge under a shared transaction. Timeline locking does not cover this registry.

Independent probe: load two registry objects from the same session; register A through the first, then B through the stale object. Both calls succeed. The persisted registry contains only B; A's file remains on disk. Session integrity reports true and export reports `completed_clean`.

Raw observation (`evidence/adversarial-probes.log`): `successful_captures:2`, `persisted_registry_count:1`, `first_registered:false`, `first_file_exists:true`, `integrity_valid:true`, `export_status:"completed_clean"`. Promotion authority remains false, but the clean evidence status is unjustified.

Remediation: serialize and refresh the artifact registry across writers, or reject stale versions before reporting success. Coordinate session, registry and timeline updates; use unique temporary paths and durable commits. Detect orphan/missing registry state before clean export. Regression: both successful captures must persist and remain addressable, or a stale write must explicitly fail; never silently discard a successful capture. Include simultaneous writers and crash interruption.

### Q03 — High for operational use — FAIL: descendant containment is incomplete

Source: Evidence Forge `src/execution.rs:185–223`. Timeout kills/waits for the direct child. A one-second drain deadline reports an error but does not contain descendants or join their surviving reader threads.

Probe: a short-lived Python parent spawns a descendant inheriting output pipes. Verification returns its drain-deadline error after **1033 ms**; the descendant subsequently writes an external sentinel. `descendant_wrote_after_return:true` is recorded. The probe descendant exits naturally after this bounded action.

Remediation: establish platform process-tree ownership before execution (Windows Job Object and an appropriate Linux process-group/container boundary), terminate and reap descendants on every completion/error/timeout path, and bound stream cleanup. Assert no child can write after return. Keep the existing conservative failure result. This confirms an already disclosed operational limit; it does not imply fixture publication claimed sandboxing.

### Q04 — High release blocker — NOT VERIFIED: authenticated provenance and hostile filesystem concurrency

All **130** files listed in the historical flight SHA256 inventory match after interpreting its Windows relative paths as path components. All **31** historical command records have the expected exit polarity. The retained Windows logs substantiate the reported 281/4 Titan outcome and the four setup failures. These establish consistency of supplied evidence, not trusted origin, completeness, or resistance to replacing a package and its hashes together.

Learning Trace explicitly exports `producer_authenticated:false` (`src/adapter/titan.rs:170`) and no promotion authority. Source inspection in F05, F07, Evidence Forge and Flight Recorder finds pathname checks followed by separate opens/writes. No controlled hostile concurrent path-swap campaign qualified those operations here. F07's passing SQLite writer/observer tests establish a narrower transaction property, not protection against external filesystem replacement.

Remediation: before claiming adversarial operational acceptance, bind producers and exact source/run identities to an independently trusted evidence anchor and define omission/completeness handling. Qualify handle-based filesystem confinement with adversarial mutation tests and documented platform boundaries. Do not present plain hashes as authenticated provenance or ordinary SQLite concurrency tests as hostile-filesystem protection.

### Q05 — Medium — FAIL: qualification harness can misstate coverage and repeatability

Published `tools/verify_all.py:12–25` records revision and dirty status but labels PASS solely from exit codes. It does not enforce the expected candidate manifest or reject dirty source, and it does not rebind/check source after execution. This is a source-established evidence-binding gap; no dirty product checkout was created for this audit.

`tests/a03.rs:697–700` returns successfully without exercising the junction when `TITAN_F03_REPARSE_MODE` is absent. The Windows file-symlink branch also substitutes a traversal test when privilege is unavailable, and the A04 optional symlink branch logs unavailability. A green test count therefore is not proof of complete real-link coverage. This limitation was disclosed in the ledger; the aggregate script does not enforce it.

The existing Unix A03 file-symlink test uses the fixed `targets/a03-29-link.json` path and unconditionally creates it without cleanup (`tests/a03.rs:667–694`). The first full run passes it; the aggregate rerun fails at line 691 with OS error 17, AlreadyExists. Reusing the build-local fixtures is not reliably repeatable.

Remediation: bind expected revisions/trees and before/after source state; reject unbound/dirty qualification. Report required coverage as EXECUTED/PASS, FAIL, or NOT_EXECUTED with reasons. Give each invocation isolated fixtures or safe test-owned cleanup. Run the unchanged security assertions in a real Windows-link-capable environment. Unsupported setup must remain a blocked gate, not an aggregate PASS.

### Q06 — Medium — FAIL gate / cause NOT VERIFIED: F06 zero-effect inventory is unstable here

First full run: 52/53 A06 tests pass; one before/after inventory assertion fails. Aggregate rerun: 35/53 pass. A serial diagnostic on retained fixtures yields 52/53; a separate fresh target with one test thread yields 51/53. No assertions were changed or skipped.

Parsed before/after differences involve **directory modification timestamps**, not file-content changes. The fresh isolated diagnostic changes only the `f05-fixtures` directory timestamp. Diff JSON files are retained. These observations do not prove K5 writes fixture content, and this audit has not established whether the timestamp behavior originates in the filesystem/runtime, test setup, or another cause. Parallelism alone is not an adequate explanation because an isolated serial run also fails.

Remediation: reproduce on local native storage with captured filesystem identity and timestamp behavior; trace actual writes; separate setup effects from evaluation. Retain the zero-effect assertion and file identity/content coverage. Do not merely remove timestamp checks or report a serial run as PASS. Acceptance requires a repeatable full gate and an explained mismatch.

### Q07 — Medium — FAIL/BLOCKED: platform reproduction and static gates

Titan `cargo fmt --all -- --check` fails on build.rs, root declarations and test formatting. Strict Clippy fails on six `unused_mut` cases compiled on Unix (capability, evidence, test_store and verification source). Raw diagnostics are retained.

Evidence Forge's 12 Linux suite failures occur in tests using Windows `cmd`/PowerShell or requiring their execution; those failures do not establish equivalent product execution failures. Its independent native-Python probe and actual Oracle execution demonstrate useful narrower behavior. Original flight also hardcodes `.exe` paths and assumes prebuilt binaries. The aggregate omits fmt/clippy and cannot provide their qualification.

A clean **online** `npm ci` from the SPC lockfile succeeds (180 packages), and all selected TS assertions then pass through the module loader. This narrows the earlier clean-install concern. It does not reproduce the historical Windows offline cache or prove an offline install from an empty cache; RuleForge's independently installed frontend dependencies were not qualified.

Remediation: restore formatting and warning-free builds without suppressing meaningful checks; use platform-aware test commands or declare and enforce a Windows-only gate. Parameterize runtime/layout/binary selection, preflight dependencies, preserve exact lockfiles, and provide explicit online-bootstrap/offline-replay expectations. Do not modify locked versions solely to make the verifier green.

### Q08 — BLOCKED: full five-tool role, browser and authority prerequisites

Learning Trace's recovered schema and adapter assess learner events; they do not implement a software-decision journal. Its 26 passing synthetic learner tests do not resolve that role mismatch. The historical flight explicitly rejects software process outcomes. No learner stream was fabricated here. Full five-tool integration remains blocked pending a narrowly approved role/contract decision.

Browser interaction, persistence after reload/restart, accessibility and recovery are **NOT VERIFIED**. No browser session was used; old screenshots or imported browser JSON were not treated as current execution. Any future browser gate needs an explicit target/plan covering controls, saved state, failure/recovery, console/network outcomes and evidence boundaries.

F08 remains outside this audit's authorization and requires separately accepted F05–F07 qualification plus its own fixture-stage authorization. Operational Root policy and the separate Phase-1 package were not re-read in their original Windows locations. Their present external bytes are NOT VERIFIED; `implementation_authorized:false`, fixture-only authority and no operational Root are frozen constraints honored throughout this review. No report or passing fixture result grants additional authority.

## Remediation order and acceptance criteria

1. **Q01 and Q02:** close the confirmed evidence-integrity defects. Preserve failing reproducers. Acceptance: real aliases rejected on supported platforms; no successful capture disappears; clean export requires complete persisted evidence.
2. **Q03 and Q04:** qualify process containment, provenance and hostile filesystem boundaries before any operational-use claim. Acceptance: no descendant effects after return; anchored producer/run identity; adversarial filesystem campaign or an explicitly bounded supported environment.
3. **Q05–Q07:** make the verification reproducible and truthful. Acceptance: exact source binding; all mandatory link cases actually executed; two consecutive full runs from clean setup; explained F06 metadata behavior; fmt/clippy/test gates pass on declared platforms. Add tests for confirmed gaps without weakening existing assertions.
4. **Q08:** resolve Learning Trace's intended role before implementing full five-tool integration. Browser and F08 work remain separate scoped gates. Do not silently repurpose the learner contract or substitute fixture authority for operational authorization.

## Handoff envelope and suggested next prompt

**New window required for remediation:** change from independent verifier to implementation owner, preserving this immutable acceptance record. Recommended: GPT-6.1 Sol, High thinking, normal speed, single agent. A later fresh verification window should independently assess the new revisions. GitHub is useful for immutable source identity; Windows/MSVC with permitted real links plus Linux are necessary for the platform claims. Browser access is only needed for a separately scoped browser verification plan.

Carry this report, its evidence package, exact revision/tree table, original ledger/publication report, companion bundles, failing probes and source manifest. Exclude credentials, caches, synthetic learner outcomes as product evidence, unsupported PASS conclusions and previous approval claims as substitutes for current evidence. Execution owner for next stage: implementation agent; user retains release, promotion, F08, operational Root and Phase-1 authority.

```text
BUBBA — Remediate the confirmed Titan qualification findings Q01–Q07 in the attached October 20 independent report.
Role: implementation/remediation engineer. Stage: QUALIFICATION FAILED → REMEDIATE → VERIFY. Use a fresh Work window, GPT-6.1 Sol, High thinking, normal speed, single agent.

Entry: verify Aimcurio/titan ID 1396000355; published candidate 2be4dfb9b51e1d88c6d0e5f603838d5bed3abfa5 / tree 33b390290c9031a66d7a4569767d92c1ac46507c; underlying source d58621eadde67e4164524586e07fc0cbb16a0fdd. Verify all five separate companion revisions/trees from the report. Preserve original histories and work only on isolated remediation branches/checkouts.

Fix F04 cross-platform hard-link rejection; recorder stale-registry data loss and unjustified clean export; Evidence Forge descendant containment. Strengthen source/coverage binding, rerunnable fixtures, platform-aware commands, fmt and Clippy. Investigate the F06 directory-timestamp mismatch with raw filesystem/write evidence before changing its assertions. Address provenance and hostile filesystem protection only to the bounded operational acceptance requirements identified in the report; do not rebuild the architecture.

Preserve every existing assertion. Add the report's adversarial reproducers as meaningful regressions. Run real Windows junction/hard-link tests with successful setup and Linux alias tests, capture exact argv/cwd/exits/raw output, and perform two clean full verification runs. Distinguish passing component suites, a partial companion flight, and full product acceptance.

Q08 role reconciliation is a separate product decision: report the exact Learning Trace alternatives and blocked integration point; do not fabricate learner data or silently replace its contract. Do not start F08 or operational Root work.

Authority: this directive authorizes bounded implementation and local testing only. No push, merge, release, deployment, enrollment, candidate promotion, Phase-1 activation or operational authority. Phase-1 remains implementation_authorized:false. Preserve separate companion histories.

Exit: provide exact new commits/trees/parents, changed-file hashes, raw before/after tests, findings resolved versus blocked, source-cleanliness evidence and a fresh independent-verification handoff. No release-qualified verdict while any required blocker remains.
```

## Evidence package contents and limits

The package retains this report, raw independent logs, command maps, manifests, source identity/hash records, inventory diagnostics, the external probe source/lockfile, and the bounded exchange driver and outputs. Historical originals remain in the separately identified input archive; this package records their verification result rather than duplicating the companion repositories.

`PACKAGE_SHA256.json` detects accidental changes relative to this package. It is not an authenticated producer signature. Original-machine preservation of all 1,070 historical source files, current external control/Phase-1 state, Windows acceptance, offline-empty-cache install, browser behavior and full five-tool integration remain outside independently verified coverage.
