# Local command-line inspection and capture

Run `python -m gargoyl --help`. The installed `gargoyl` console script is not part
of this initial module-entry change. Existing `python -m gargoyl.dashboard` and
`python -m gargoyl.foreground --check-config ...` remain separate tools.

Inspect already supplied output without executing anything:

```sh
python -m gargoyl inspect status --input saved-status.txt --observed-at 2026-01-01T00:00:00Z
python -m gargoyl inspect doctor --input - --observed-at 2026-01-01T00:00:00Z
```

`--observed-at` must be the actual UTC observation time, not the time a saved file
was opened. File/stdin input is limited to 64 KiB and parsed strictly as UTF-8.
Only fixed normalized metrics leave the parser; source text is not echoed or
saved. Supported text formats are defined exclusively by the collector parsers.
Unsupported or ambiguous formats return `invalid_state`, never guessed success.

For an explicitly intended acquisition, the operator supplies all execution
configuration:

```sh
python -m gargoyl capture status --executable /absolute/trusted/producer --cwd /absolute/working/directory --environment /absolute/explicit-environment.json
```

Use `doctor` instead of `status` to request that fixed upstream argument. The
mandatory environment file is a bounded UTF-8 JSON string-to-string object; `{}`
is valid. Duplicate keys are rejected. Nothing from the parent environment is
inherited. There is no shell, executable discovery, environment/key enrollment,
credential lookup, configuration discovery, service management or repair command.
The operator must assess the chosen executable and its environment: upstream
status/doctor may themselves read keys/files, run helpers or access the network.
This acquisition is not an OS sandbox or a claim of side-effect-free execution.

Capture uses the existing acquisition budget: five seconds including one second
reserved for terminate/kill/reap cleanup, with 64 KiB combined stdout/stderr.
Raw stderr is counted and discarded. Filesystem/config reads, process launch and
OS scheduling are not forcibly bounded. SIGINT/SIGTERM request cleanup; repeated
signals do not skip cleanup. Incomplete cleanup is reported without claiming
child containment. No background loop, network delivery, store or retry is added.

Output is one JSON object containing `schema_version: 1`, `source_kind`,
`observed_at`, normalized `readings` and fixed `errors`. Capture additionally
includes `completed_at` and `cleanup_complete`. This is a transient CLI result,
not a telemetry snapshot, signed receipt or durable authenticated repair. Source
observations retain their timestamp and TTL; the CLI does not assess fleet health.
No host identity, repair claim or authority is invented. Captured or parsed data
is emitted only to stdout; operators control any subsequent redirection/storage.

| Exit | Meaning |
| --- | --- |
| 0 | Valid observation, including stopped status or a completed failed doctor check. Not overall health. |
| 1 | Parsing/acquisition failed; errors are fixed codes and no partial readings establish success. |
| 2 | Arguments, input access or configuration unavailable/invalid; fixed stderr, no JSON result. |
| 3 | Acquisition cleanup incomplete; no readings and no permission to retry automatically. |
| 130 | Interruption with verified acquisition cleanup; no readings. |

Tests use only temporary files and self-authored synthetic executables, including
real timeout and signal cleanup checks. They do not establish production source
compatibility beyond the parser's supported formats or authorize live operation.
