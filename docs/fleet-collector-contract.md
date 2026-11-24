# Current fleet collector/management contract

This is the implemented private read-only projection in `fleet_management.py`,
not an unauthenticated remote ingestion API or enrollment mechanism.

Inputs are the exact normalized account inventory, fresh local public-identity
proof from the protected state/native-process reader, and at most64validated v1
snapshots for one configured local telemetry UUID. The actual account provider ID
is never replaced with that UUID. The projection rejects mixed-host snapshots.
Public identity is joined only when the complete connected inventory and local
proof are fresh and exactly one returned provider matches. Aliases, status claims,
reported heartbeats and request-supplied labels do not establish a collector.

Each returned row preserves its provider ID and source name/kind; account report
and heartbeat freshness remain separate from direct process-evidence state.
`local_associated` means a verified mapping to this Mac, not healthy or executable.
`tailscale_peer` means a validated snapshot from a peer matched to this provider by
exact, unique Tailscale name. It's an observation, not authenticated identity or control.
`inventory_only` means no verified direct collector association in this app, not a
claim that the remote machine is offline. Missing history is None/unknown, never
fabricated zero usage. `native_review` is a workflow hint requiring fresh independent
preflight and per-attempt owner confirmation, not an execution grant. Remote restart
is unavailable. The data is reconstructed for the native view, not persisted or
added to public loopback reports/exports.

A future remote collector must separately establish authenticated transport identity,
per-host scope and provider-identity association before any remote action can be
offered. The read-only Tailscale telemetry library (`gargoyl/tailscale.py`, see
`docs/tailscale-telemetry.md`) checks only the client's address range, so it carries
observations, never authority. No credentials, enrollment, key creation, extra log
collection or automatic action is implemented here. Until those dependent steps are
explicitly authorized, providers without validated peer telemetry remain account
inventory records with honest unavailable reasons. This boundary does not block
current local tools.

## Table presentation

Rows must stay distinguishable: each cell shows only a value that can vary per
row (reported status, heartbeat freshness, version, coverage state). Account
report freshness belongs in the account summary because it comes from one read.
Unusually large status and version values may be shortened to keep the table
within the native view limit. Each provider's detail view shows its full values.
The invariants that are true of every inventory row — no verified direct
collector association, no remote history in this app (absence is not zero
activity), and no provider-control grant, so no enrollment, remote command or
restart is ever initiated for an inventory row — are stated once in a shared
coverage note under the table, not repeated per row. The associated
"this Mac" row differs in every coverage cell and is visually distinct.
