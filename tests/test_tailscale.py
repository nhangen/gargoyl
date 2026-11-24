"""Tests for Tailscale node discovery, peer telemetry endpoint, and fleet federation."""

import json
import re
import threading
import unittest
import urllib.error
import urllib.request

from test_dashboard import HOST, snapshot
from test_fleet_state import NOW, response

from gargoyl import tailscale
from gargoyl.fleet_management import management_html, management_projection
from gargoyl.fleet_state import normalize_inventory, provider_key
from gargoyl.native_views import render_view, valid_view
from gargoyl.tailscale import (
    FleetTelemetryStore,
    TailscaleTelemetryServer,
    associate_peers_with_providers,
    discover_peers,
    is_tailscale_ip,
    make_telemetry_snapshot,
    match_peers_to_providers,
    parse_tailscale_status,
)

SAMPLE_TAILSCALE_STATUS = {
    "Version": "1.76.0",
    "Self": {
        "ID": "node-self-1",
        "HostName": "mbp-2026",
        "DNSName": "mbp-2026.example.ts.net.",
        "OS": "macOS",
        "TailscaleIPs": ["100.80.1.1", "fd7a:115c:a1e0::1"],
        "Online": True,
    },
    "Peer": {
        "peer-studio32-1": {
            "ID": "node-peer-2",
            "HostName": "studio32-1",
            "DNSName": "studio32-1.example.ts.net.",
            "OS": "macOS",
            "TailscaleIPs": ["100.80.1.2", "fd7a:115c:a1e0::2"],
            "Online": True,
        },
        "peer-studio64-1": {
            "ID": "node-peer-3",
            "HostName": "studio64-1",
            "DNSName": "studio64-1.example.ts.net.",
            "OS": "macOS",
            "TailscaleIPs": ["100.80.1.3", "fd7a:115c:a1e0::3"],
            "Online": True,
        },
        "peer-studio64-2": {
            "ID": "node-peer-4",
            "HostName": "studio64-2",
            "DNSName": "studio64-2.example.ts.net.",
            "OS": "macOS",
            "TailscaleIPs": ["100.80.1.4", "fd7a:115c:a1e0::4"],
            "Online": True,
        },
        "peer-offline": {
            "ID": "node-peer-5",
            "HostName": "studio-offline",
            "DNSName": "studio-offline.example.ts.net.",
            "OS": "macOS",
            "TailscaleIPs": ["100.80.1.5"],
            "Online": False,
        },
        "peer-linux": {
            "ID": "node-peer-6",
            "HostName": "linux-worker",
            "DNSName": "linux-worker.example.ts.net.",
            "OS": "linux",
            "TailscaleIPs": ["100.80.1.6"],
            "Online": True,
        },
    },
}


class TailscaleDiscoveryTests(unittest.TestCase):
    def test_parse_tailscale_status_filters_macos_and_online(self):
        status = parse_tailscale_status(SAMPLE_TAILSCALE_STATUS)
        self.assertEqual(status["version"], "1.76.0")
        self.assertEqual(status["self"]["hostname"], "mbp-2026")
        self.assertEqual(status["self"]["tailscale_ipv4"], "100.80.1.1")

        peers = status["peers"]
        # Only online macOS peers should be included (studio32-1, studio64-1, studio64-2)
        # offline and linux peers must be excluded
        hostnames = [p["hostname"] for p in peers]
        self.assertEqual(hostnames, ["studio32-1", "studio64-1", "studio64-2"])
        for p in peers:
            self.assertTrue(p["online"])
            self.assertIn(p["os"].lower(), ("macos", "darwin"))
            self.assertTrue(p["tailscale_ipv4"].startswith("100."))

    def test_parse_tailscale_status_string_input(self):
        raw_json = json.dumps(SAMPLE_TAILSCALE_STATUS)
        status = parse_tailscale_status(raw_json)
        self.assertEqual(len(status["peers"]), 3)

    def test_parse_tailscale_status_invalid_fails_gracefully(self):
        with self.assertRaises(ValueError):
            parse_tailscale_status("not valid json")
        with self.assertRaises(ValueError):
            parse_tailscale_status(123)

    def test_discover_peers_from_data(self):
        peers = discover_peers(SAMPLE_TAILSCALE_STATUS)
        self.assertEqual(len(peers), 3)
        self.assertEqual([p["hostname"] for p in peers], ["studio32-1", "studio64-1", "studio64-2"])

    def test_match_peers_to_providers_exact_and_fuzzy(self):
        peers = discover_peers(SAMPLE_TAILSCALE_STATUS)
        providers = [
            {"id": "prov-studio32-1", "name": "studio32-1"},
            {"id": "prov-studio64-1", "name": "Studio64-1"},
            {"id": "prov-studio64-2", "name": "studio64-2-cluster"},
            {"id": "prov-unmatched", "name": "other-device"},
        ]
        matched = match_peers_to_providers(peers, providers)
        self.assertIn("prov-studio32-1", matched)
        self.assertEqual(matched["prov-studio32-1"]["hostname"], "studio32-1")
        self.assertIn("prov-studio64-1", matched)
        self.assertEqual(matched["prov-studio64-1"]["hostname"], "studio64-1")
        self.assertIn("prov-studio64-2", matched)
        self.assertEqual(matched["prov-studio64-2"]["hostname"], "studio64-2")
        self.assertNotIn("prov-unmatched", matched)

    def test_associate_peers_with_providers_auto_aliasing(self):
        peers = discover_peers(SAMPLE_TAILSCALE_STATUS)
        providers = [
            {"id": "prov-studio32-1", "name": "studio32-1"},
            {"id": "prov-studio64-1", "name": "studio64-1"},
        ]
        aliases = associate_peers_with_providers(peers, providers)
        self.assertEqual(aliases, {
            "prov-studio32-1": "studio32-1",
            "prov-studio64-1": "studio64-1",
        })


class TailscaleSecurityTests(unittest.TestCase):
    def test_is_tailscale_ip_validation(self):
        # 100.64.0.0/10 range
        self.assertTrue(is_tailscale_ip("100.64.0.1"))
        self.assertTrue(is_tailscale_ip("100.80.1.25"))
        self.assertTrue(is_tailscale_ip("100.127.255.254"))

        # Tailscale IPv6 ULA
        self.assertTrue(is_tailscale_ip("fd7a:115c:a1e0::1"))
        self.assertTrue(is_tailscale_ip("fd7a:115c:a1e0:ab12::34"))

        # Loopback
        self.assertTrue(is_tailscale_ip("127.0.0.1", allow_loopback=True))
        self.assertFalse(is_tailscale_ip("127.0.0.1", allow_loopback=False))

        # Rejected unauthorized / non-Tailscale IPs
        self.assertFalse(is_tailscale_ip("192.168.1.1"))
        self.assertFalse(is_tailscale_ip("10.0.0.1"))
        self.assertFalse(is_tailscale_ip("172.16.0.1"))
        self.assertFalse(is_tailscale_ip("8.8.8.8"))
        self.assertFalse(is_tailscale_ip("1.1.1.1"))
        self.assertFalse(is_tailscale_ip("not-an-ip"))
        self.assertFalse(is_tailscale_ip(None))

    def test_unauthorized_interface_rejected_with_403(self):
        # Start server with allow_loopback=False, so localhost connects are rejected as non-Tailscale
        server = TailscaleTelemetryServer(
            ("127.0.0.1", 0),
            telemetry_provider=lambda: make_telemetry_snapshot({"hostname": "test-host"}),
            allow_loopback=False,
        )
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            url = f"http://127.0.0.1:{port}/v1/telemetry"
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(url, timeout=2)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class TailscaleEndpointAndFederationTests(unittest.TestCase):
    def setUp(self):
        self.server = None
        self.thread = None

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2)

    def test_telemetry_snapshot_contents(self):
        snap = make_telemetry_snapshot(
            node_info={"hostname": "studio32-1", "tailscale_ip": "100.80.1.2"},
            daemon_state="running",
            current_model="deepseek-coder-v2-lite",
            resident_models=["deepseek-coder-v2-lite", "qwen2.5-coder-7b"],
            gpu_memory_active_gb=18.5,
            running_requests=3,
            tokens_generated=1420500,
            memory_headroom_bytes=16000000000,
            now=NOW,
        )
        self.assertEqual(snap["node"]["hostname"], "studio32-1")
        self.assertEqual(snap["daemon_state"]["value"], "running")
        self.assertEqual(snap["models"]["current_model"], "deepseek-coder-v2-lite")
        self.assertEqual(snap["models"]["resident_models"], ["deepseek-coder-v2-lite", "qwen2.5-coder-7b"])
        self.assertEqual(snap["models"]["gpu_memory_active_gb"], 18.5)
        self.assertEqual(snap["throughput"]["running_requests"], 3)
        self.assertEqual(snap["throughput"]["tokens_generated"], 1420500)
        self.assertEqual(snap["memory_headroom_bytes"], 16000000000)

    def test_telemetry_server_get_telemetry_and_history(self):
        mock_snapshot = make_telemetry_snapshot(
            node_info={"hostname": "studio32-1", "tailscale_ip": "100.80.1.2"},
            daemon_state="running",
            current_model="qwen2.5-coder-7b",
            gpu_memory_active_gb=14.0,
            running_requests=2,
            tokens_generated=500000,
            now=NOW,
        )
        self.server = TailscaleTelemetryServer(
            ("127.0.0.1", 0),
            telemetry_provider=lambda: mock_snapshot,
            allow_loopback=True,
        )
        port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

        # Query endpoint
        store = FleetTelemetryStore()
        result = store.poll_peer("127.0.0.1", provider_id="prov-1", port=port)
        self.assertIsNotNone(result)
        self.assertEqual(result["node"]["hostname"], "studio32-1")
        self.assertEqual(result["models"]["current_model"], "qwen2.5-coder-7b")

        # Check rolling history
        stored = store.get("prov-1")
        self.assertEqual(len(stored["recent_history"]), 1)
        self.assertEqual(stored["recent_history"][0]["current_model"], "qwen2.5-coder-7b")

        # Ingest multiple to verify 64-sample rolling bound
        for i in range(70):
            store.ingest("prov-1", mock_snapshot)
        self.assertEqual(len(store.get("prov-1")["recent_history"]), 64)

    def _serve(self, **kwargs):
        self.server = TailscaleTelemetryServer(("127.0.0.1", 0), **kwargs)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        return self.server.server_port

    def test_operator_restart_route_is_not_served(self):
        port = self._serve(telemetry_provider=lambda: {"node": {}}, allow_loopback=True)
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/operator/restart",
            data=json.dumps({"preflight_confirmed": True}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=2)
        self.assertEqual(ctx.exception.code, 405)
        self.assertFalse(hasattr(tailscale, "remote_operator_restart"))

    def test_telemetry_without_provider_is_unavailable_not_observed(self):
        port = self._serve(allow_loopback=True)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/telemetry", timeout=2)
        self.assertEqual(ctx.exception.code, 503)

    def test_inspect_route_is_not_served(self):
        port = self._serve(telemetry_provider=lambda: {"node": {}}, allow_loopback=True)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/operator/inspect", timeout=2)
        self.assertEqual(ctx.exception.code, 404)

    def test_server_requires_explicit_address_and_rejects_loopback_by_default(self):
        with self.assertRaises(TypeError):
            TailscaleTelemetryServer()
        port = self._serve(telemetry_provider=lambda: {"node": {}})
        with self.assertLogs("gargoyl.tailscale", level="WARNING") as logs:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/telemetry", timeout=2)
        self.assertEqual(ctx.exception.code, 403)
        self.assertTrue(any("127.0.0.1" in line for line in logs.output))


class MultiNodeFleetFederationTests(unittest.TestCase):
    def setUp(self):
        raw = response()
        # Add fleet nodes matching the operator's real fleet: studio32-1, studio64-1, studio64-2
        raw["providers"] = [
            {"id": "prov-mbp-2026", "name": "mbp-2026", "status": "online", "version": "0.10.6",
             "last_heartbeat": NOW, "se_public_key": "fixture-public-key"},
            {"id": "prov-studio32-1", "name": "studio32-1", "status": "online", "version": "0.10.6",
             "last_heartbeat": NOW, "se_public_key": "studio32-key"},
            {"id": "prov-studio64-1", "name": "studio64-1", "status": "online", "version": "0.10.6",
             "last_heartbeat": NOW, "se_public_key": "studio64-1-key"},
            {"id": "prov-studio64-2", "name": "studio64-2", "status": "online", "version": "0.10.6",
             "last_heartbeat": NOW, "se_public_key": "studio64-2-key"},
        ]
        raw["total_count"] = 4
        self.inventory = normalize_inventory(raw, NOW)
        self.local = dict(identity_digest=provider_key("fixture-public-key"), observed_at=NOW)
        self.evidence = dict(evaluated_at=NOW, snapshots=[snapshot(source="host", at=NOW)])

    def test_peer_telemetry_replaces_inventory_only_and_none_here(self):
        # Without peer telemetry: remote machines are "Inventory only" and "None here"
        proj_unfederated = management_projection(
            self.inventory, self.local, self.evidence, NOW, HOST, peer_telemetry=None
        )
        html_unfederated = management_html(proj_unfederated, {})
        self.assertIn("Inventory only", html_unfederated)
        self.assertIn("None here", html_unfederated)

        # Build mock peer telemetry for all remote nodes
        store = FleetTelemetryStore()
        nodes = [
            ("prov-studio32-1", "studio32-1", "100.80.1.2", "deepseek-coder-v2-lite", 18.5, 3, 250000),
            ("prov-studio64-1", "studio64-1", "100.80.1.3", "qwen2.5-coder-32b", 34.0, 5, 890000),
            ("prov-studio64-2", "studio64-2", "100.80.1.4", "llama-3.1-70b", 42.0, 4, 1200000),
        ]
        for prov_id, host, ip, model, gpu_gb, reqs, tokens in nodes:
            snap = make_telemetry_snapshot(
                node_info={"hostname": host, "tailscale_ip": ip},
                daemon_state="running",
                current_model=model,
                resident_models=[model],
                gpu_memory_active_gb=gpu_gb,
                running_requests=reqs,
                tokens_generated=tokens,
                history_samples=[{"sample": 1}, {"sample": 2}],
                now=NOW,
            )
            store.ingest(prov_id, snap)

        peer_map = store.as_provider_map()

        # With federated peer telemetry:
        proj_federated = management_projection(
            self.inventory, self.local, self.evidence, NOW, HOST, peer_telemetry=peer_map
        )
        html_federated = management_html(proj_federated, {})

        # "Inventory only" and "None here" should no longer appear in the table rows
        self.assertNotIn("Inventory only", html_federated)
        self.assertNotIn("None here", html_federated)

        # Peer telemetry and workflows must be rendered
        self.assertIn("Tailscale peer · studio32-1", html_federated)
        self.assertIn("Tailscale peer · studio64-1", html_federated)
        self.assertIn("Tailscale peer · studio64-2", html_federated)
        self.assertIn("deepseek-coder-v2-lite (18.5 GB GPU)", html_federated)
        self.assertIn("qwen2.5-coder-32b (34.0 GB GPU)", html_federated)
        self.assertIn("llama-3.1-70b (42.0 GB GPU)", html_federated)
        self.assertNotIn("Pre-drained", html_federated)
        self.assertNotIn("remote operator restart", html_federated)
        self.assertEqual(html_federated.count("Telemetry only · no remote control"), 3)
        for href in re.findall(r'href="gargoyl-view://([^"/]+)/"', html_federated):
            self.assertTrue(valid_view(href), href)

    def test_render_fleet_with_peer_telemetry(self):
        store = FleetTelemetryStore()
        snap = make_telemetry_snapshot(
            node_info={"hostname": "studio32-1", "tailscale_ip": "100.80.1.2"},
            daemon_state="running",
            current_model="deepseek-coder-v2-lite",
            gpu_memory_active_gb=18.5,
            running_requests=2,
            tokens_generated=450000,
            now=NOW,
        )
        store.ingest("prov-studio32-1", snap)
        peer_map = store.as_provider_map()

        page = render_view(
            "fleet",
            self.evidence,
            None,
            inventory=self.inventory,
            local=self.local,
            local_alias="mbp-2026",
            now=NOW,
            peer_telemetry=peer_map,
        )

        # Peer badge should be present
        self.assertIn("Tailscale peer", page)
        self.assertIn("studio32-1", page)
        self.assertIn("live telemetry", page)

        # Detail view for peer node
        detail_view = "fleet-node-" + provider_key("prov-studio32-1")
        detail_page = render_view(
            detail_view,
            self.evidence,
            None,
            inventory=self.inventory,
            local=self.local,
            local_alias="mbp-2026",
            now=NOW,
            peer_telemetry=peer_map,
        )
        self.assertIn("studio32-1 (100.80.1.2)", detail_page)
        self.assertIn("deepseek-coder-v2-lite", detail_page)
        self.assertIn("18.5 GB", detail_page)
        self.assertNotIn("Pre-drained", detail_page)
        self.assertIn("Telemetry only · no remote control", detail_page)
        for page_html in (page, detail_page):
            for href in re.findall(r'href="gargoyl-view://([^"/]+)/"', page_html):
                self.assertTrue(valid_view(href), href)


if __name__ == "__main__":
    unittest.main()
