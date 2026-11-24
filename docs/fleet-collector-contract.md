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
`tailscale_peer` indicates an authenticated peer node on the operator's Tailscale
tailnet, exposing normalized native daemon state, active models, real-time throughput,
and rolling history samples over `/v1/telemetry`, with preflight-verified remote operator restarts.
`inventory_only` means no verified direct collector association in this app, not a
claim that the remote machine is offline. Missing history is None/unknown, never
fabricated zero usage. `native_review` is a workflow hint requiring fresh independent
preflight and per-attempt owner confirmation, not an execution grant.
The data is reconstructed for the native view, not persisted or
added to public loopback reports/exports.

Tailscale peer federation (`gargoyl/tailscale.py`) discovers online macOS peer nodes
over the private tailnet, validates client IP addresses against the Tailscale CGNAT subnet
(`100.64.0.0/10`) and IPv6 range, and streams normalized peer snapshots into the fleet
store. Discovered peer hostnames automatically map to Darkbloom provider identities, replacing
empty `Inventory only` and `None here` table cells with live telemetry and remote operator workflows.

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
