# Collector library integration

This is a read-only library, not an installed host daemon. It executes no host
commands. `collector.collect` accepts complete v1 observations for its fixed
SOURCES metrics; source adapters must map command-specific enums locally and
never pass raw output, labels, model names or error messages. Missing observations
become unknown. Invalid/extra fields are rejected rather than silently exported.
Errors are limited to 32 fixed codes per collection; the current schema retains
only the latest code, not an event timeline. Source timestamps and staleness are
preserved. Clock skew is unknown unless a trusted reference time is supplied.

Supply a separately provisioned CollectionIdentity and SpoolCipher and a
RetentionPolicy to `collector_history.EncryptedHistory(directory, cipher, policy,
now)`. Use a private application-owned directory under a trusted parent. The
single-writer SQLite history contains encrypted payloads and local sequence/ack
metadata only. Startup, append and pending reads enforce age/count retention in
transactions. Failed writes roll back; corrupt ciphertext and wrong keys fail
closed. No key or plaintext snapshot is written by this library. Pruning is not
a guarantee of forensic secure erasure; expired ciphertext may remain in backups
or filesystem snapshots. The store must have a single collector owner; no
multi-process scheduler or directory replacement by another actor is supported.

Call collect and history.append on a regular independent collection schedule.
Call deliver_pending separately with an injected monotonic clock and RetrySchedule;
it attempts at most one retained snapshot, backs off on failure, and marks a
record delivered only after success. Delivered history remains until retention
expires. Collection continues while delivery waits or fails. Call history.close
on shutdown. Retention can evict undelivered data during long outages; delivery is
at-least-once and the receiver must deduplicate replay after an acknowledgement
crash. Retry state resets on process restart. No background threads are started.

OutboundHTTPS uses the foundation TransportConfig TLS context and collection
identity, revalidates immediately before POST, rejects redirects and treats only
200/201/204 as acknowledgements. The receiver contract must make these statuses
mean durable acceptance, enforce certificate-to-host binding and revocation, and
deduplicate snapshots. It must not use 202 as durable acknowledgement. No response
body or exception text is collected. Tests mock network I/O; they do not prove a
live mTLS handshake. A missing or expired collector heartbeat is an incident via
collector.heartbeat_incident, even when other metrics appear healthy.

Outstanding integration: actual Darkbloom/macOS read-only source adapters, host
service scheduling, secure key/certificate enrollment and storage, receiver
implementation, crash/power-loss testing on the target filesystem, and explicit
three-host validation. Do not close issue #2 based on synthetic library tests.

Run from the worktree:

    python -m venv --system-site-packages /workspace/collector-venv
    /workspace/collector-venv/bin/python -m pip install -e .
    /workspace/collector-venv/bin/python -m unittest discover -s tests -v
