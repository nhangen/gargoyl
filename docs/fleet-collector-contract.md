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
`inventory_only` means no verified direct collector association in this app, not a
claim that the remote machine is offline. Missing history is None/unknown, never
fabricated zero usage. `native_review` is a workflow hint requiring fresh independent
preflight and per-attempt owner confirmation, not an execution grant. Remote restart
is unavailable. The data is reconstructed for the native view, not persisted or
added to public loopback reports/exports.

A future remote collector must separately establish authenticated transport identity,
per-host scope and provider-identity association before any observations can enter
this projection. No remote input adapter, credentials, enrollment, key creation,
extra log collection or automatic action is implemented here. Until those dependent
steps are explicitly authorized, other providers remain account inventory records
with honest unavailable reasons. This boundary does not block current local tools.
