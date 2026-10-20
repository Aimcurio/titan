# Recording and undoing Titan development

## The terms in plain language

- A **commit** is a saved version of changed files, with an explanation, author, date, and link to the preceding version. Its long identifier lets us recover that exact state.
- A **branch** is a named line of work in the same repository. Titan currently keeps the baseline and completion candidate on separate branches.
- A **push** copies local saved commits to GitHub. A local commit is not backed up on GitHub until the upload succeeds and the remote result is checked.
- A **merge** brings one line of work into another. Recording an audit does not require merging the code it assessed.
- A **revert** adds a new commit that reverses an earlier change. This keeps a visible record of both the change and its undo operation.

## For each future work session

1. Read `STATUS.md`, the latest development-log entry, and the actual local Git status. Identify the exact source and intended branch before editing; do not assume a laptop copy and GitHub already match.
2. Make a bounded change on an appropriate development branch. Preserve unfinished and failed work honestly; use small commits with meaningful messages. Keep separate companion histories separate.
3. Record what changed and why, tests actually run, failures, and remaining uncertainty. Add raw evidence or reference its exact location and checksum. A blocked session should get a history entry even when it creates no source revision.
4. Inspect the diff for unintended files and sensitive data. Exclude credentials, caches, build products, and unrelated project material.
5. Save a commit, then publish when authorized. Confirm the returned remote revision and important file contents. Update `STATUS.md` and `DEVELOPMENT_HISTORY.md` as the work progresses.

This guide does not create an automatic backup or scheduled synchronization. Each future upload needs to be executed and checked. A branch name or a passing component test does not establish full product acceptance.

## When a change needs to be undone

Use Git's file history to inspect the saved versions first. For a published change, normally add a revert commit so the original change and reversal are both visible. Recover individual files from an exact earlier commit when that is the intended scope. Preserve uncommitted work before switching versions. Avoid force pushes and destructive history rewrites; they undermine the shared record the requester wants to keep.

## Evidence records

Preserve imported original evidence bytes under a dated folder. Put context and later corrections beside the originals rather than editing the originals to fit a newer conclusion. Include source revisions, test environment, commands/results, and provenance limits. Checksum agreement detects changed bytes; it does not by itself authenticate who produced the evidence.

Keep development publication separate from release, qualification, deployment, Phase-1 activation, F08, and operational Root authority. Publishing unfinished work and documenting defects is part of development history.
