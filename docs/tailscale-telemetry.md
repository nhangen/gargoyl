# Tailscale peer telemetry

`gargoyl/tailscale.py` is the library layer for observing other fleet Macs over a
Tailscale tailnet. It isn't wired into the native app yet: nothing starts the
telemetry server or polls peers, and `render_view` receives peer telemetry only when
a caller passes `peer_telemetry`. Wiring is tracked separately.

## Discovery

- `get_tailscale_status` runs `/Applications/Tailscale.app/Contents/MacOS/Tailscale
  status --json`, or `tailscale` on `PATH`. A missing CLI, non-zero exit, timeout, or
  unparseable output returns `None` and logs the reason.
- `parse_tailscale_status` keeps peers whose `OS` is macOS or Darwin and whose
  `Online` is `true`.
- `match_peers_to_providers` associates a peer with a Darkbloom provider only when the
  cleaned provider name exactly equals the peer's hostname or first DNS label, and
  only when the match is unique in both directions. Ambiguous or partial names stay
  unmatched.

## Telemetry endpoint

- `TailscaleTelemetryServer` serves `GET /v1/telemetry` only. The caller must pass
  the bind address; bind it to the node's own Tailscale IP.
- Requests from outside `100.64.0.0/10` and `fd7a:115c:a1e0::/48` get HTTP 403 and
  are logged. Loopback is rejected unless `allow_loopback=True`. The address check is
  not authentication: `100.64.0.0/10` is shared carrier-grade NAT space, and any
  tailnet member passes it.
- Without a `telemetry_provider`, the endpoint returns HTTP 503 rather than a
  placeholder snapshot. Other methods return HTTP 405.
- No operator action is served. Remote restart stays unavailable until authenticated
  transport identity exists (see `docs/fleet-collector-contract.md`).

## Fleet store

- `FleetTelemetryStore.ingest` validates each snapshot with `validate_peer_snapshot`
  and rejects malformed fields, recording the reason in `last_error`.
- Values a peer didn't report stay `None`; a missing daemon state is `unavailable`,
  never `running`.
- Each provider keeps a 64-sample rolling history.
- `poll_peer` records why a poll failed (`unreachable`, `http_error`,
  `invalid_json`, `oversized`, `invalid_snapshot`) and keeps the last good snapshot.

## Presentation

When peer telemetry is supplied, **Your fleet** and **Fleet management** show the
peer's hostname, daemon state, models, GPU memory, throughput, and retained sample
count in place of `Inventory only` / `None here`. Peer rows are telemetry only and
offer no remote control.
