# Local pilot installation policy

Normal use stays graphical. The existing MBP-26 installation needs no file edit,
terminal step or new sign-in. With no policy file, the approved defaults remain
UID501, `MBP-2026.local`, the existing local telemetry UUID, the inspected
`~/.darkbloom` layout, loopback8766 and the same manual confirmation/preflight.
The monitor CLI is now the sibling of the selected isolated Python interpreter;
no Codex task-directory path is compiled into the runtime.

An installer may supply one optional policy at
`~/Library/Application Support/Gargoyl/pilot.json`. This delivery creates no live
policy and installs nothing on another host. Installing a nondefault policy provisions an admissible local manual-action
target and requires separate target-specific authorization. It is not a remote
grant or permission to execute a provider action; native confirmation and all
preflight checks still apply. No such target provisioning occurs in this delivery.

## Validation

The parent directory must be canonical, owner-owned and0700. The file must be an
owned regular single-link0600 file, with no symlink traversal, at most8192bytes and
unchanged metadata across its bounded read. Invalid, nonprivate, duplicate-key,
malformed or unsupported policy fails closed; it never falls back to defaults.
No secrets, arguments, network endpoints, credentials or raw source content belong
in this file. No environment override or arbitrary policy path is accepted.

Schema1 has exactly these keys:

| Key | Constraint |
|---|---|
| `schema` | Integer1 |
| `owner_uid` | Nonroot current owner UID; booleans rejected |
| `hostname` | Exact current kernel hostname; bounded printable hostname syntax |
| `host_id` | Canonical opaque telemetry UUID; not a Darkbloom account provider ID |
| `source` | Current owner's inspected `.darkbloom/daemon-state.json` path |
| `provider_executable` | Current owner's inspected `.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom` path |
| `monitor_executable` | `gargoyl` beside the selected isolated Python, not an arbitrary command |
| `versions` | Nonempty map of reviewed version strings to the catalog's recorded build hashes; may only narrow that catalog |

Schema2 has the same keys plus `grants`, written only by the native app's
Permissions & Activation flow after a typed confirmation:

| Key | Constraint |
|---|---|
| `schema` | Integer2 |
| `grants` | One of the fixed ordered sets of `provider_executable`, `operator_tools`, `restart`, `account_read_only`; a dependent grant requires its prerequisites, and `[]` revokes everything |

Each grant maps1:1 to a monitor flag: `provider_executable` to
`--provider-executable <path> --coordinator-errors`, `operator_tools` to
`--operator-tools`, `restart` to `--enable-restart`. `account_read_only` adds no
flag. Saving changes only `grants`; owner, hostname, telemetry identity and a
narrowed `versions` carry over unchanged.

### Unrecorded policy and enforcement

With no policy file, or a schema1 file, no grant set has been recorded and the
approved pilot behavior stays exactly as before: the monitor job carries the
provider flags, and manual restart and the read-only account remain available
behind their own confirmations. Once a schema2 file exists, its grants are
enforced everywhere: every manual restart path (native, `gargoyl tools restart`,
the operator console and an already-running monitor) refuses without `restart`
in `installation_preflight`, and every account session mode refuses without
`account_read_only`. A running monitor keeps the flags it was started with until
it is stopped and started; the restart refusal applies to it immediately.

### Monitor job writer

Saving grants rewrites `~/Library/LaunchAgents/dev.gargoyl.monitor.plist` with the
implied argument vector, `RunAtLoad` and `KeepAlive` off. An existing file is
replaced only when it is an owned, single-link, non-group/world-writable plist
labelled `dev.gargoyl.monitor`; anything else is refused unchanged. If the plist
write fails, the previous `pilot.json` is restored, so the policy and the job never
disagree. Nothing is loaded or started.

The policy binds one local installation. It cannot select another owner, a remote
hostname, a custom provider/configuration layout, an arbitrary executable or a new
operation. It does not bootstrap a service, start a provider, change the monitor
LaunchAgent beyond the grants writer above, or bypass native Mac owner confirmation.
Outside that writer, a mismatching existing monitor job is refused, not rewritten. The configured telemetry identity is passed
through normalized export and native views; it never replaces an account provider ID.

## Compatibility approval

The shared compatibility catalog covers only inspected Darkbloom0.10.5/0.10.6
parser and command semantics. A policy cannot authorize a newer release by listing
its version or hash. Supporting a release requires inspecting matching upstream
source and supported output, recording its provenance, updating the catalog and
its tests, and independent reviewed passing delivery. No live restart is needed
to establish parser support.

The recorded hashes remain provenance, as before; the manual path still checks
owned canonical executable identity/stamp, fresh native process identity,
state/CLI version agreement and provider/watchdog preconditions. This change does
not invent binary-signature verification or silently make a new hash trust rule.
Read-only diagnostic parsing uses the reviewed catalog; the installation policy's
subset further restricts manual execution. Journal parsing retains the catalog so
old records remain readable if execution policy narrows.

The only config writer is the per-capability grants flow above. No provisioning grant, automatic repair or remote backend is added.
