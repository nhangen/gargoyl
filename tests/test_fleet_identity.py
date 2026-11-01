import copy
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from test_fleet_state import NOW, response

from gargoyl.fleet_identity import local_identity, matching_provider
from gargoyl.fleet_state import normalize_inventory


class IdentityTests(unittest.TestCase):
    def state(self, path, **changes):
        at = datetime.fromisoformat(NOW.replace("Z", "+00:00")).timestamp()
        data = dict(
            schema=1,
            pid=123,
            version="0.10.6",
            written_at=at,
            started_at=at - 100,
            inference_active=False,
            warm_models=[],
            stats={},
            process_identity=dict(pid=123, start_time_micros=int((at - 100) * 1e6)),
            attestation_public_key="fixture-public-key",
            coordinator_url="wss://api.darkbloom.dev/ws/provider",
        )
        data.update(changes)
        path.write_text(json.dumps(data))
        path.chmod(0o600)

    def test_protected_public_identity_matches_actual_provider_id_not_hostname(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "state.json"
            self.state(path)
            local = local_identity(
                str(path), "/test-image", os.getuid(), NOW, verifier=lambda _: True
            )
            self.assertNotIn("fixture-public-key", json.dumps(local))
            inventory = normalize_inventory(response(), NOW)
            self.assertEqual(
                matching_provider(inventory, local, NOW),
                "provider-real-format-test-only",
            )
            for field in ["identity_digest", "observed_at"]:
                self.assertIn(field, local)
            wrong = copy.deepcopy(local)
            wrong["identity_digest"] = "0" * 64
            self.assertIsNone(matching_provider(inventory, wrong, NOW))
            inventory["providers"].append(
                dict(inventory["providers"][0], id="ambiguous-other-provider")
            )
            self.assertIsNone(matching_provider(inventory, local, NOW))

    def test_missing_public_key_wrong_coordinator_and_unverified_process_fail_closed(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "state.json"
            for change in [
                dict(attestation_public_key=None),
                dict(coordinator_url="wss://evil.test/ws/provider"),
                dict(coordinator_url=None),
            ]:
                self.state(path, **change)
                with self.assertRaises(ValueError):
                    local_identity(
                        str(path),
                        "/test-image",
                        os.getuid(),
                        NOW,
                        verifier=lambda _: True,
                    )
            self.state(path)
            with self.assertRaises(ValueError):
                local_identity(
                    str(path), "/test-image", os.getuid(), NOW, verifier=lambda _: False
                )
            linked = path.with_name("linked.json")
            linked.symlink_to(path)
            with self.assertRaises((OSError, ValueError)):
                local_identity(
                    str(linked),
                    "/test-image",
                    os.getuid(),
                    NOW,
                    verifier=lambda _: True,
                )

    def test_stale_disconnected_and_ambiguous_local_binding_never_used(self):
        inventory = normalize_inventory(response(), NOW)
        local = dict(
            identity_digest=inventory["providers"][0]["identity_digest"],
            observed_at=NOW,
            local_alias="local fixture",
        )
        self.assertIsNone(matching_provider(inventory, local, "2026-11-02T00:00:00Z"))
        self.assertIsNone(matching_provider(inventory, local, "2026-10-31T00:00:00Z"))
        missing = dict(local, identity_digest=None)
        inventory["providers"][0]["identity_digest"] = None
        self.assertIsNone(matching_provider(inventory, missing, NOW))
        inventory["connection"] = "disconnected"
        self.assertIsNone(matching_provider(inventory, local, NOW))
