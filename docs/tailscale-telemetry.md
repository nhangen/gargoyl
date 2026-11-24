# Tailscale Tailnet Telemetry and Fleet Federation

## Overview

Rather than treating the operator's Mac fleet (`mbp-2026`, `studio32-1`, `studio64-1`, `studio64-2`) as isolated silos with empty `Inventory only` and `None here` placeholders, Gargoyl integrates directly with the private Tailscale tailnet to provide true fleet-wide telemetry, observability, and remote operator controls.

## 1. Tailscale Node Discovery & Auto-Aliasing (`gargoyl/tailscale.py`)

- **Discovery**: Queries local Tailscale status via `/Applications/Tailscale.app/Contents/MacOS/Tailscale status --json` (or `tailscale status --json` on `PATH`) to discover active nodes on the operator's tailnet.
- **Filtering**: Filters for peer nodes where `OS` is macOS (`macOS` / `Darwin`) and `Online` is `true`.
- **Auto-Aliasing**: Matches discovered online Tailscale peer hostnames (e.g. `studio32-1`, `studio64-1`, `studio64-2`, `mbp-2026`) against Darkbloom provider identities by source label / hostname, automatically providing friendly hostnames without manual guesswork.

## 2. Peer Telemetry Endpoint (`/v1/telemetry`)

- **Interface Protection**: Telemetry endpoints bind to the Tailscale interface or enforce a subnet guard.
- **Subnet Guard**: Rejects incoming requests from non-Tailscale interfaces with HTTP 403 Forbidden. Only addresses within the Tailscale CGNAT range (`100.64.0.0/10`) or Tailscale IPv6 ULA (`fd7a:115c:a1e0::/48`), plus numeric loopback (`127.0.0.1`), are authorized.
- **Snapshot Payload**: The read-only `/v1/telemetry` endpoint exposes:
  - `node`: Hostname, Tailscale IP, and provider association.
  - `daemon_state`: Normalized daemon state (`value`, `state`, `source`, `timestamp`).
  - `models`: Active model residency, `current_model`, `resident_models`, and `gpu_memory_active_gb`.
  - `throughput`: Real-time request and token counters (`running_requests`, `tokens_generated`, `requests_total`, `tokens_total`).
  - `memory_headroom_bytes`: Unified memory headroom bytes.
  - `recent_history`: Bounded 64-sample rolling history buffer.
  - `collected_at`: UTC timestamp.

## 3. Fleet Telemetry Aggregation / Federation

- **Federated Collector**: Gargoyl's collector on the operator workstation periodically polls online tailnet peers over their private `100.x.x.x` IPs.
- **Fleet Store (`FleetTelemetryStore`)**: Aggregates peer evidence into the fleet store, maintaining a 64-sample rolling history per node.
- **Live Presentation**: Replaces empty `Inventory only` and `None here` table cells in **Your fleet** (`render_fleet`) and **Fleet management** (`management_html`):
  - Native daemon state & health (`running`, `observed`).
  - Active loaded models with GPU memory usage (`current_model (XX.X GB GPU)`).
  - Real-time throughput (running requests and tokens generated).
  - Rolling history links and retained sample counts per peer.
  - Operator workflow links for remote pre-drained restarts.

## 4. Remote Operator Workflows over Tailscale

- **Preflight Verification**: Operator workflows across tailnet nodes require explicit preflight confirmation.
- **Pre-Drained Restart (`POST /v1/operator/restart`)**:
  - Initiates a safe, graceful restart across tailnet peers.
  - Rejects any unconfirmed or malformed request with HTTP 400.
  - Rejects non-Tailscale connections with HTTP 403.
  - Enforces atomic journal locking and pre-drained state reconciliation on the target node.
