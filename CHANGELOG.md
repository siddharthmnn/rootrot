# changelog

notable changes to rootrot are recorded here. entries stay under `unreleased` until a version is actually tagged.

## unreleased

### added

- modular runtime configuration, execution context and simulator registry.
- bounded file inspection with streaming sha-256 and file-type mismatch telemetry.
- platform-specific persistence examples that do not modify the host.
- expiring, authenticated in-memory task queues with replay checks.
- non-destructive ransomware targeting previews and in-memory staging manifests.
- modular behavioural detection rules with severity scoring and run-scoped correlation.
- event filtering, jsonl import/export, timelines and hash-chain checkpoints.
- self-contained json and html forensic reports.
- automated ci, coverage checks, package verification and contributor tooling.

### changed

- python 3.11 is now the minimum supported version.
- the command line supports explicit event and report export paths.
- package development tools are available through the `dev` optional dependency group.

### security and safety

- report writers use atomic replacement and do not overwrite existing output unless requested.
- event imports enforce size and count limits and can verify the event hash chain.
- html report content is escaped before rendering.
- simulation behaviour remains local and non-destructive.
