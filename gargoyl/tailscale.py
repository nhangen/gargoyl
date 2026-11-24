"""Tailscale tailnet node discovery, a read-only peer telemetry endpoint, and fleet aggregation.

Remote operator actions are deliberately not served here: mutations stay local and
owner-confirmed (docs/hardening-decisions.md) until authenticated transport exists.
"""

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from gargoyl.telemetry import timestamp

TAILSCALE_IPV4_SUBNET = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_IPV6_SUBNET = ipaddress.ip_network("fd7a:115c:a1e0::/48")
DEFAULT_TAILSCALE_PATH = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
DEFAULT_TELEMETRY_PORT = 8342
MAX_HISTORY_PER_NODE = 64

log = logging.getLogger(__name__)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def is_tailscale_ip(ip_str: str, allow_loopback: bool = True) -> bool:
    """Validate whether an IP address belongs to the Tailscale CGNAT or IPv6 subnet."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if allow_loopback and ip.is_loopback:
            return True
        return ip in TAILSCALE_IPV4_SUBNET or ip in TAILSCALE_IPV6_SUBNET
    except ValueError:
        return False


def _normalize_node(raw: dict) -> dict | None:
    if not isinstance(raw, dict):
        return None
    hostname = raw.get("HostName") or raw.get("Host") or ""
    dns_name = (raw.get("DNSName") or "").rstrip(".")
    os_name = raw.get("OS") or ""
    online = bool(raw.get("Online", False))
    raw_ips = raw.get("TailscaleIPs") or []
    ts_ips = []
    ipv4 = None
    for ip in raw_ips:
        if isinstance(ip, str):
            ts_ips.append(ip)
            if ipv4 is None and is_tailscale_ip(ip, allow_loopback=False):
                try:
                    if ipaddress.ip_address(ip).version == 4:
                        ipv4 = ip
                except ValueError:
                    pass
    return {
        "id": str(raw.get("ID", "")),
        "hostname": str(hostname),
        "dns_name": dns_name,
        "os": str(os_name),
        "online": online,
        "tailscale_ips": ts_ips,
        "tailscale_ipv4": ipv4,
    }


def parse_tailscale_status(raw_data: str | bytes | dict) -> dict:
    """Parse output from `tailscale status --json`.

    Extracts Self and online macOS peers on the tailnet.
    """
    if isinstance(raw_data, (str, bytes)):
        try:
            data = json.loads(raw_data)
        except Exception as exc:
            raise ValueError(f"invalid tailscale status json: {exc}") from exc
    elif isinstance(raw_data, dict):
        data = raw_data
    else:
        raise ValueError("invalid tailscale status data type")

    self_node = _normalize_node(data.get("Self") or {})
    peers = []
    peers_raw = data.get("Peer")
    if isinstance(peers_raw, dict):
        for peer_id, peer_obj in peers_raw.items():
            node = _normalize_node(peer_obj)
            if node is not None:
                if not node["id"]:
                    node["id"] = str(peer_id)
                # Filter for macOS peers that are online
                if node["os"].lower() in {"macos", "darwin"} and node["online"]:
                    peers.append(node)
    elif isinstance(peers_raw, list):
        for peer_obj in peers_raw:
            node = _normalize_node(peer_obj)
            if node is not None and node["os"].lower() in {"macos", "darwin"} and node["online"]:
                peers.append(node)

    peers.sort(key=lambda p: p["hostname"].lower())
    return {
        "version": str(data.get("Version", "unknown")),
        "self": self_node,
        "peers": peers,
    }


def get_tailscale_status(executable: str | None = None, timeout: float = 5.0) -> dict | None:
    """Query local Tailscale status via CLI.

    Returns parsed status dict, or None if Tailscale is not installed / not running.
    """
    cli_path = executable
    if cli_path is None:
        if os.path.exists(DEFAULT_TAILSCALE_PATH) and os.access(DEFAULT_TAILSCALE_PATH, os.X_OK):
            cli_path = DEFAULT_TAILSCALE_PATH
        else:
            cli_path = shutil.which("tailscale")
    if not cli_path:
        return None

    try:
        res = subprocess.run(
            [cli_path, "status", "--json"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if res.returncode != 0:
            return None
        return parse_tailscale_status(res.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None


def discover_peers(status_data: dict | None = None, executable: str | None = None) -> list[dict]:
    """Identify online macOS peer nodes on the tailnet."""
    if status_data is None:
        status_data = get_tailscale_status(executable=executable)
    elif isinstance(status_data, dict) and ("Peer" in status_data or "Self" in status_data):
        status_data = parse_tailscale_status(status_data)
    if not status_data or not isinstance(status_data, dict):
        return []
    return list(status_data.get("peers") or [])


def _clean_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def match_peers_to_providers(peers: list[dict], providers: list[dict]) -> dict[str, dict]:
    """Associate discovered Tailscale peer nodes with Darkbloom provider identities.

    Matches by exact or fuzzy hostname / source label.
    Returns: {provider_id: peer_dict}
    """
    matches = {}
    used_peers = set()

    # Pass 1: exact match between provider name and peer hostname
    for provider in providers:
        prov_id = provider.get("id")
        prov_name = provider.get("name") or provider.get("source_name") or ""
        prov_clean = _clean_name(prov_name)
        if not prov_id or not prov_clean:
            continue
        for peer in peers:
            peer_id = peer.get("id") or peer.get("hostname")
            if peer_id in used_peers:
                continue
            peer_host_clean = _clean_name(peer.get("hostname", ""))
            peer_dns_clean = _clean_name(peer.get("dns_name", "").split(".")[0])
            if prov_clean in (peer_host_clean, peer_dns_clean):
                matches[prov_id] = peer
                used_peers.add(peer_id)
                break

    # Pass 2: prefix / substring match (e.g. mbp-provider <-> mbp-2026 or studio64-1 <-> studio64)
    for provider in providers:
        prov_id = provider.get("id")
        if not prov_id or prov_id in matches:
            continue
        prov_name = provider.get("name") or provider.get("source_name") or ""
        prov_clean = _clean_name(prov_name)
        if not prov_clean:
            continue
        for peer in peers:
            peer_id = peer.get("id") or peer.get("hostname")
            if peer_id in used_peers:
                continue
            peer_host_clean = _clean_name(peer.get("hostname", ""))
            if prov_clean in peer_host_clean or peer_host_clean in prov_clean:
                matches[prov_id] = peer
                used_peers.add(peer_id)
                break

    return matches


def associate_peers_with_providers(peers: list[dict], providers: list[dict]) -> dict[str, str]:
    """Generate friendly auto-aliases: {provider_id: peer_hostname}."""
    matched = match_peers_to_providers(peers, providers)
    return {prov_id: peer["hostname"] for prov_id, peer in matched.items() if peer.get("hostname")}


def make_telemetry_snapshot(
    node_info: dict,
    daemon_state: str | None = None,
    current_model: str | None = None,
    resident_models: list[str] | None = None,
    gpu_memory_active_gb: float | None = None,
    running_requests: int | None = None,
    tokens_generated: int | None = None,
    memory_headroom_bytes: int | None = None,
    history_samples: list[dict] | None = None,
    now: str | None = None,
) -> dict:
    """Build a peer telemetry snapshot; values not observed stay None."""
    at = now or utc_now_iso()
    timestamp(at)
    res_models = list(resident_models) if resident_models else ([] if not current_model else [current_model])
    model_state = "resident" if res_models else "absent"

    return {
        "node": dict(node_info),
        "daemon_state": {
            "value": daemon_state,
            "state": "observed" if daemon_state is not None else "unavailable",
            "source": "host",
            "timestamp": at,
        },
        "models": {
            "current_model": current_model,
            "resident_models": res_models,
            "gpu_memory_active_gb": gpu_memory_active_gb,
            "model_state": model_state,
        },
        "throughput": {
            "running_requests": running_requests,
            "tokens_generated": tokens_generated,
            "requests_total": running_requests,
            "tokens_total": tokens_generated,
        },
        "memory_headroom_bytes": memory_headroom_bytes,
        "recent_history": list(history_samples or [])[-MAX_HISTORY_PER_NODE:],
        "collected_at": at,
    }


def _optional(value, kinds, field):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, kinds):
        raise ValueError(f"invalid {field}")
    return value


def _section(snapshot: dict, name: str) -> dict:
    value = snapshot.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"invalid {name}")
    return value


def validate_peer_snapshot(snapshot) -> dict:
    """Normalize an untrusted peer snapshot; raises ValueError on any malformed field."""
    if not isinstance(snapshot, dict):
        raise ValueError("invalid snapshot")
    node = _section(snapshot, "node")
    daemon = _section(snapshot, "daemon_state")
    models = _section(snapshot, "models")
    throughput = _section(snapshot, "throughput")
    resident = models.get("resident_models") or []
    if not isinstance(resident, list) or not all(isinstance(m, str) for m in resident):
        raise ValueError("invalid resident_models")
    collected_at = snapshot.get("collected_at")
    if collected_at is not None:
        try:
            timestamp(collected_at)
        except Exception as exc:
            raise ValueError("invalid collected_at") from exc
    daemon_value = _optional(daemon.get("value"), str, "daemon_state.value")
    return {
        "node": {
            "hostname": _optional(node.get("hostname"), str, "node.hostname"),
            "tailscale_ipv4": _optional(node.get("tailscale_ipv4"), str, "node.tailscale_ipv4"),
        },
        "daemon_state": {
            "value": daemon_value,
            "state": "observed" if daemon_value is not None else "unavailable",
        },
        "models": {
            "current_model": _optional(models.get("current_model"), str, "models.current_model"),
            "resident_models": list(resident),
            "gpu_memory_active_gb": _optional(models.get("gpu_memory_active_gb"), (int, float), "models.gpu_memory_active_gb"),
        },
        "throughput": {
            "running_requests": _optional(throughput.get("running_requests"), int, "throughput.running_requests"),
            "tokens_generated": _optional(throughput.get("tokens_generated"), int, "throughput.tokens_generated"),
        },
        "memory_headroom_bytes": _optional(snapshot.get("memory_headroom_bytes"), int, "memory_headroom_bytes"),
        "collected_at": collected_at,
    }


class TailscaleTelemetryHandler(BaseHTTPRequestHandler):
    """Read-only HTTP handler serving /v1/telemetry to Tailscale peers."""

    server_version = "GargoylTailscale/1.0"
    sys_version = ""
    timeout = 5

    def log_message(self, format, *args):
        pass

    def _respond(self, status: int, data: dict):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _check_auth(self) -> bool:
        client_ip = self.client_address[0]
        if not is_tailscale_ip(client_ip, allow_loopback=self.server.allow_loopback):
            log.warning("rejected telemetry request from non-Tailscale address %s", client_ip)
            self._respond(
                403,
                {"error": "unauthorized_interface", "message": "Tailscale interface required"},
            )
            return False
        return True

    def do_GET(self):
        if not self._check_auth():
            return
        if self.path not in ("/v1/telemetry", "/v1/telemetry/"):
            self._respond(404, {"error": "not_found"})
            return
        provider = self.server.telemetry_provider
        if not callable(provider):
            self._respond(503, {"error": "telemetry_provider_not_configured"})
            return
        self._respond(200, provider())

    def _method_not_allowed(self):
        if not self._check_auth():
            return
        self._respond(405, {"error": "method_not_allowed"})

    do_POST = do_PUT = do_PATCH = do_DELETE = _method_not_allowed
    do_HEAD = do_GET


class TailscaleTelemetryServer(HTTPServer):
    """Read-only telemetry server; the caller chooses the bind address explicitly."""

    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], telemetry_provider=None, allow_loopback: bool = False):
        self.telemetry_provider = telemetry_provider
        self.allow_loopback = allow_loopback
        super().__init__(address, TailscaleTelemetryHandler)


class FleetTelemetryStore:
    """Store aggregating validated peer telemetry and 64-sample rolling history per node."""

    def __init__(self, max_history: int = MAX_HISTORY_PER_NODE):
        self.max_history = max_history
        self._nodes: dict[str, dict] = {}
        self._history: dict[str, deque] = {}
        self._errors: dict[str, dict] = {}

    def _record_error(self, provider_id: str, kind: str, detail: str):
        self._errors[provider_id] = {"at": utc_now_iso(), "kind": kind, "detail": detail}
        log.warning("peer telemetry for %s rejected: %s (%s)", provider_id, kind, detail)

    def last_error(self, provider_id: str) -> dict | None:
        return self._errors.get(provider_id)

    def ingest(self, provider_id: str, telemetry_snapshot) -> bool:
        """Validate and store a snapshot; returns False and records the reason when rejected."""
        if not provider_id:
            return False
        try:
            data = validate_peer_snapshot(telemetry_snapshot)
        except ValueError as exc:
            self._record_error(provider_id, "invalid_snapshot", str(exc))
            return False
        history = self._history.setdefault(provider_id, deque(maxlen=self.max_history))
        history.append({
            "collected_at": data["collected_at"],
            "daemon_state": data["daemon_state"]["value"],
            "current_model": data["models"]["current_model"],
            "running_requests": data["throughput"]["running_requests"],
            "tokens_generated": data["throughput"]["tokens_generated"],
        })
        self._nodes[provider_id] = data
        self._errors.pop(provider_id, None)
        return True

    def get(self, provider_id: str) -> dict | None:
        """Get latest telemetry snapshot with rolling history for a provider."""
        entry = self._nodes.get(provider_id)
        if not entry:
            return None
        res = dict(entry)
        res["recent_history"] = list(self._history.get(provider_id, []))
        return res

    def as_provider_map(self) -> dict[str, dict]:
        """Return dict of {provider_id: telemetry_snapshot} for all ingested nodes."""
        return {prov_id: self.get(prov_id) for prov_id in self._nodes}

    def poll_peer(
        self,
        peer_ip: str,
        provider_id: str,
        port: int = DEFAULT_TELEMETRY_PORT,
        timeout: float = 3.0,
    ) -> dict | None:
        """Fetch telemetry snapshot from a peer over Tailscale and ingest it."""
        try:
            url = f"http://{peer_ip}:{port}/v1/telemetry"
            req = urllib.request.Request(url, headers={"User-Agent": "GargoylCollector/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    self.ingest(provider_id, data)
                    return data
        except Exception:
            return None
        return None
