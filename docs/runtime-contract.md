# Local runtime integration contract

This slice connects encrypted collection to authenticated ingestion and dashboard
evidence inside local tests. It does not install services, enroll identities,
configure credentials, run upstream host commands or establish pilot acceptance.
Telemetry v1 and the interfaces in [contract.md](contract.md) remain unchanged.

## Ownership and source evidence

Foundation owns `ingestion.py`, `ingestion_http.py`, their tests and this document.
Collector owns source adapters and collection/delivery scheduling. Dashboard owns
its separate read-only viewer and consumes the structural reader below. No lane
introduces a second scaffold, repair runner or production hosting framework.

Source-format reference: [Darkbloom provider main.rs at a6f7f483](https://github.com/darkbloomdev/darkbloom/blob/a6f7f483ab88806c633e37e00339c13e37ab62f4/provider/src/main.rs).
The Rust producer emits status text with running/stopped markers and doctor text
with eight numbered checks plus `Result: N/8 checks passed`. Status's model label
is log-derived, not proof of current residency. Parser fixtures may match these
verified formats, but remain synthetic and do not establish live compatibility.
Do not execute `status` or `doctor` as part of these tests; they perform additional
filesystem/network reads. Foundation tests use normalized synthetic v1 evidence;
source-parser integration belongs to the collector lane and subsequent combined tests.

## Evidence store

```python
EvidenceStore(directory, ciphers_by_host, policy, now)
store.accept(snapshot, *, now) -> bool
store.snapshots(*, now) -> list[dict]
store.close()
```

`ciphers_by_host` maps canonical opaque UUIDs to matching existing `SpoolCipher`
objects, using explicit externally supplied receiver keys. `policy` is a foundation
`RetentionPolicy`. The configured inventory is 1..16 hosts, with the product of host
count and policy.max_records at most 10000. No automatic enrollment or inventory
expansion occurs. Use a private application-owned directory under a trusted parent.
Symlink database files, nonprivate files/directories and hardlinked database files
are rejected. The parent directory must not be replaceable by another actor.

SQLite holds encrypted snapshot payloads; opaque host UUID, sequence and canonical
SHA-256 deduplication digest are plaintext operational metadata. Keys and raw source
input are never persisted. DELETE journaling and FULL synchronous commits establish
the local durability boundary; this is not a hardware power-loss certification or
forensic secure-erasure guarantee. Backups may retain expired ciphertext.

Every operation authenticates and validates all bounded stored records before
retention decisions. Each host retains its newest policy.max_records entries whose
collection time is not older than policy.max_age_seconds. Future-relative records
remain within that same count cap and are returned to the dashboard as evidence;
the existing projection marks them unknown. Startup, accepts and reads apply
retention transactionally. Reading can therefore prune expired records.

`snapshots` returns a detached, transactionally consistent complete list across
configured hosts, independent of collector pending/ack state. Empty means no retained
evidence, not a successful health verdict. `EvidenceReadError("evidence unavailable")`
means corruption, wrong keys, missing inventory keys, invalid stored metadata or
storage/read failure: never substitute an empty/partial healthy view. Construction
also reports storage/setup failures with this generic error; invalid explicit
inventory/policy arguments fail before filesystem operations.

`accept` validates and encrypts before insertion and returns exactly True only
after commit. Exact canonical snapshot retries return True without another record.
Dedupe lasts only while that record is retained. Reports differing in any canonical
content remain separate, including same-host/source/timestamp contradictions and
separate collection timestamps. Expired input or a record excluded by count limits
is not acknowledged. Failure to commit or authenticate existing history raises
safe `EvidenceWriteError`; malformed input and unknown host authorization fail
closed. Receivers may not treat an exception as durable acceptance.

### Thread ownership

One `EvidenceStore` instance can be shared by ingestion and dashboard threads.
A reentrant lock serializes complete SQLite transactions, including all validation,
pruning and detached reads; the SQLite connection explicitly permits cross-thread
use. The caller must stop/join listener threads before `store.close()`. Do not access
private connection fields. No background threads or process scheduler are created
by the store. Multiple processes, migrations and production topology are outside
this slice; use one owning process and the same store instance for both listeners.

## Certificate authorization and HTTPS

```python
Principal(host_ids=frozenset(...), grants=frozenset({(metric, source), ...}))
IngestionService(store, principals_by_certificate_sha256)
service.accept(payload: bytes, peer_certificate_der: bytes, *, now) -> bool
```

Registry keys are lowercase 64-character SHA-256 fingerprints of DER client
certificates. At most 64 principals are configured. Every envelope host and every
metric/source pair must be granted. Trusting the certificate chain alone does not
grant access; unknown fingerprints fail. A host collector's grants need its fixed
collector/unknown observations as well as actual readings. A narrowly granted
`(coordinator_reachable, coordinator)` pair does not grant coordinator daemon,
routing, model or console earnings authority. No repair capability exists.

Only a verified mTLS socket may supply peer certificate bytes to this service;
this method is an internal boundary, not a replacement for TLS chain validation.
Untrusted callers cannot self-assert certificate bytes over HTTP headers. The
registry is copied at construction. Revocation/rotation require deliberate caller
replacement/restart; there is no enrollment API or dynamic credential configuration.

```python
make_ingestion_server(
    service, *, ca_file, certificate_file, private_key_file, clock,
    host="localhost", port=0, timeout=2,
)
```

Returns an unstarted `HTTPServer`-compatible server. The caller owns
`serve_forever`, `shutdown` and `server_close`. Only localhost binding is allowed;
this is a bounded local integration server, not public fleet hosting. TLS >=1.2,
explicit CA trust and required client certificates are enforced before HTTP. Each
socket has a configured finite inactivity timeout (0..10 seconds, exclusive of 0).
Requests are processed serially; this slice does not promise resistance to a local
slow-client denial of service.

- `POST /v1/snapshots`, exactly one Content-Length and Content-Type application/json.
- One v1 payload, at most 65536 bytes. Transfer/content encodings and Expect are rejected.
- 204 with an empty body only after durable acceptance or retained exact duplicate.
- 400 malformed input/framing; 403 unknown peer or unauthorized host/source;
  413 invalid body size; 404 other routes; 405 GET; 503 storage/service failure.
- No redirects, user-facing error details, request-body logs, peer-address logs,
  repair routes, dashboard routes or plaintext ingestion fallback.

Collector keeps existing OutboundHTTPS and deliver_pending APIs, targeting
`https://localhost:<test-port>/v1/snapshots` in tests. Production endpoint deployment
is separately authorized work. Dashboard owns a separate read-only loopback viewer
using structural `snapshots(*, now)` plus explicit expected-host inventory and an
injected clock, evaluating at request time with refresh <=60 seconds. A missing
expected host remains visible; storage failure must show unavailability.

## Verification and limitations

From the dedicated worktree:

1. `python -m venv .venv`
2. `.venv/bin/python -m pip install -e '.[dev]'`
3. `.venv/bin/python -m ruff check .`
4. `.venv/bin/python -m unittest discover -s tests -v`

Receiver tests generate short-lived synthetic keys/certificates under temporary
directories and establish actual local TLS handshakes. They cover required client
certificates, trust/hostname checks, fingerprint/host/source authorization, strict
framing, persistence failures, duplicate delivery, encrypted collector-to-receiver
history and dashboard heartbeat aging, restart, corruption, concurrent access,
retention and conflicting/future evidence. No real prompts, logs, host identifiers,
credentials or customer data are used. No production credential store is changed.
Live source execution, certificate/key lifecycle, real host transport, production
availability, process-level repair separation, power-loss testing and the three-host
pilot remain unverified. Epics #1–3 stay open.
