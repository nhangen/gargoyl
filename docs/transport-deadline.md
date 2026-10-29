# Bounded outbound transport

`OutboundHTTPS(config, identity, *, total_timeout_seconds=10.0,
connect_address=None)` makes one synchronous mTLS POST. The timeout must be finite,
greater than zero, and at most 30 seconds; booleans are invalid. The public timeout
attribute is available for foreground scheduler budgeting. No worker thread,
subprocess, implicit proxy, address discovery, or retry is started by the sender.

## Constructor compatibility change

Numeric endpoint hosts connect directly. `localhost` deterministically connects to
IPv4 loopback, without invoking a resolver. Other hostnames now require an explicit
numeric `connect_address`; there is no DNS fallback. This is an application input,
not a DNS or access configuration action. Scoped IPv6 addresses are unsupported.
A numeric endpoint cannot be redirected to a different numeric address; localhost
can only use a loopback address. All explicit input validation precedes reading
CA/certificate/key files. Those files remain separately provisioned inputs.

The original endpoint hostname is always used for TLS certificate verification/SNI
and the HTTP Host authority, even with an explicit destination. Hostname checks,
CA validation and client certificate authentication remain enabled. Destination
selection never authorizes an otherwise untrusted server. TLS trust setup occurs
at construction and its filesystem latency is outside the send budget.

## Deadline and acknowledgement

A monotonic deadline starts at `send()`. TCP connection, TLS handshake, request
write, and every response-header read use the remaining time. Continuous response
bytes cannot extend this deadline. Input validation is bounded by telemetry v1;
the sender checks remaining time before network operations and before accepting
an acknowledgement. OS scheduling and local CPU stalls can delay return: this is
bounded network waiting, not a hard real-time process guarantee.

The sender requires complete, strictly parsed HTTP/1.0 or HTTP/1.1 response headers
within the deadline, at most 32 KiB total and 100 fields. Obsolete folded headers,
ambiguous Content-Length, Transfer-Encoding, partial/truncated headers, and a 204
claiming a nonempty body are rejected. Interim responses are not acknowledged.
Only 200, 201 and 204 mean durable acceptance under the existing receiver contract;
202, redirects and errors do not. No response body is read, and no redirect is
followed. Reading one TLS application byte at a time avoids HTTP body prefetch.
TLS itself may internally buffer encrypted records; no body is exposed or parsed.

Timeout raises a fixed `TimeoutError('outbound deadline exceeded')`; network/TLS
failure raises a fixed `OSError('outbound transmission failed')`. Response bytes,
endpoint details, certificate paths and exception text are never logged or stored.
The connection is closed on success, failure, or interruption.

`deliver_pending()` remains unchanged: a failed attempt retains unacknowledged
ciphertext and schedules backoff. A response lost after durable receiver acceptance
can cause replay; receiver deduplication remains necessary. The bounded age/count
retention policy can still evict records during prolonged outages.

## Foreground timing and operator diagnostics

A synchronous cycle needs its acquisition budgets plus one outbound timeout plus
local validation/storage overhead. Work can delay collection; there is no claim
of uninterrupted cadence. The foreground scheduler should resume with one due
collection and avoid catch-up bursts. SQLite/filesystem blocking is outside this
network deadline. Graceful shutdown may wait for the remaining network budget;
there is no separate sender cancellation worker or asynchronous kill mechanism.

Transport failure means delivery is unconfirmed, not that collection failed or
that a provider is unhealthy. Resume collection after the attempt returns; show
last source/collection times and existing stale/unknown labels. A fresh collector
heartbeat does not establish successful source acquisition. Telemetry v1 has one
aggregate latest error code and cannot attribute multiple simultaneous failures
or expose a detailed transport failure history. Do not infer extra diagnostics.

## Tests and outstanding integration

`tests/test_transport_deadline.py` uses ephemeral synthetic certificates and local
TLS peers for timely acknowledgements, status/header byte dripping, stalled TLS,
hostname verification, retention after timeout and later collection/delivery.
Focused fake sockets test shared phase budgets and header bounds without depending
on OS buffer sizes. No real upstream acquisition command or host asset is used.

Run `python -m ruff check .` and `python -m unittest discover -s tests -v`.
The existing transport tests now exercise the socket/TLS boundary rather than the
removed HTTPSConnection adapter. The lost-ack integration case still performs real
mTLS and durable acceptance before injecting loss, then proves retained pending
history and deduplicated successful replay. Acquisition/foreground end-to-end
acceptance awaits their pinned contracts and implementation. Production identity,
DNS lifecycle, live host installation, and pilot acceptance remain separate work.
