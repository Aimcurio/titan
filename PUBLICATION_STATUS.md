# Source publication and qualification boundary

Target: https://github.com/Aimcurio/titan (repository ID `1396000355`).

This branch is based on original source commit `d58621eadde67e4164524586e07fc0cbb16a0fdd` / tree `177081bfe5ab44c1c3d5488e089cf1df0f3e90ad`. Publication documentation is appended in a separate commit; `src/`, `tests/`, build files, and lockfiles remain byte-identical to that source tree. The existing commits, authors, timestamps, and ancestry are preserved.

The original baseline is `08328274bed440e8ba0c1747a9984bab21c1a740`. The completion source `d58621eadde67e4164524586e07fc0cbb16a0fdd` has that baseline as its direct parent. The source history also retains the frozen F06 boundary `6843addb00da0e87bddd40b8de6570fd16a99ca3`. Original baseline and completion documentation are separate descendants; no candidate implementation is merged into the baseline during publication.

`main` represents the existing fixture development baseline. `completion/20261018` is an unqualified development candidate. A branch name, source upload, historical review, or GitHub repository is not release acceptance or operational authority.

## Publication audit scope

Before remote publication, verify all reachable history, including deleted file versions. The local preparation inspected 10 original commits and 57 unique historical blobs. A targeted credential-pattern scan found no credential matches; manual inspection identified machine-specific fixture paths and a campaign checkpoint location. Those paths are disclosed historical implementation metadata, not credentials. They remain in immutable history; no claim is made that the repository has been stripped of every local path. Removing them from earlier commits would change source identity and require an explicit history-rewrite decision.

Build products, dependency caches, raw external evidence/logs, local control records, original architecture/Phase-1 packages, and the five companion repositories are outside the Titan publication. The baseline's absolute paths also limit clean-machine reproduction. No proprietary or local path/Git dependency appears in Titan's Cargo manifests or lockfile; dependencies are registry packages, with bundled SQLite selected. This is not a dependency license or supply-chain qualification.

## Separate companion histories

These exact candidates were reconciled to the October 20 source manifest. They are not vendored, merged, submoduled, or pushed by this Titan publication.

| Component | Candidate commit | Candidate tree |
|---|---|---|
| spc-remediation | `bf49ca990ffcbd89ff2d95b4b92369ab041ca8b3` | `061debc49e3795b6a8a44091c41872a66ba5b21a` |
| ruleforge-engine | `537689eadacbfe6ec0e6821d140102371f63d5bc` | `021f834ae1563576da3a51a8f81c6cac5d46310e` |
| evidence-forge | `6db96efc919bf82d8c449d22856497b132759827` | `314e76d8529b02e9297b1749debacb0408c865f4` |
| learning-trace | `fbd7ee6cc1e1e0217879ffe6df808f2c3374b3e0` | `84018eec16714733423b8266d1bc5d1738a51758` |
| flight-recorder | `8bae95274141bc94681b8675d41d049163b040ec` | `260e80823c907da1e19cdc270b611eeb227c122b` |

The historical completion ledger and raw evidence remain external. Its reported passes apply only to their stated test scope. Learning Trace's role mismatch and all other release blockers remain open. The original campaign scripts require the corresponding external checkout layout and dependencies.

## Verification requirement

Publish using normal non-force Git operations only after checking current remote refs. Stop on unrelated history, missing source, or unresolved sensitive material. Verify remote branch SHAs, commit trees and essential files against the prepared local refs after transfer. No successful publication or release qualification is asserted by this document.
