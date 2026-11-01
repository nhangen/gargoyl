import os
import stat
import tempfile
import unittest
from pathlib import Path

from test_fleet_state import NOW, response

from gargoyl.fleet_aliases import AliasStore, alias_text
from gargoyl.fleet_state import FleetCache, normalize_inventory
from gargoyl.gui_runtime import alias_inventory, set_local_alias
from gargoyl.native_views import render_view


class AliasTests(unittest.TestCase):
    def test_edit_is_private_local_and_preserves_real_identity_and_source(self):
        inventory = normalize_inventory(response(), NOW)
        identity = inventory["providers"][0]["id"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            store = AliasStore(root / "private", os.getuid())
            store.set(identity, "Studio One", inventory)
            aliases = store.read()
            self.assertEqual(aliases, {identity: "Studio One"})
            self.assertEqual(
                stat.S_IMODE((root / "private/aliases.json").stat().st_mode), 0o600
            )
            self.assertEqual(stat.S_IMODE((root / "private").stat().st_mode), 0o700)
            page = render_view(
                "fleet", None, None, inventory=inventory, aliases=aliases, now=NOW
            )
            for value in [
                "Studio One",
                "Local alias · source name “Fixture Mac”",
                identity,
                "source name",
            ]:
                self.assertIn(value, page)
            self.assertEqual(inventory["providers"][0]["name"], "Fixture Mac")
            store.set(identity, "", inventory)
            self.assertEqual(store.read(), {})

    def test_unlisted_provider_and_spoofing_alias_never_written(self):
        inventory = normalize_inventory(response(), NOW)
        identity = inventory["providers"][0]["id"]
        with tempfile.TemporaryDirectory() as directory:
            store = AliasStore(Path(directory).resolve() / "private", os.getuid())
            for provider, label in [
                ("unlisted", "Name"),
                (identity, "bad\u202ename"),
                (identity, "bad\nname"),
                (identity, "x" * 65),
                (identity, "\ud800"),
            ]:
                with self.assertRaises(ValueError):
                    store.set(provider, label, inventory)
            self.assertEqual(store.read(), {})
        self.assertEqual(alias_text("  Studio One  "), "Studio One")

    def test_alias_file_symlink_or_hardlink_cannot_be_followed_or_overwritten(self):
        inventory = normalize_inventory(response(), NOW)
        identity = inventory["providers"][0]["id"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            private = root / "private"
            private.mkdir(mode=0o700)
            outside = root / "outside"
            outside.write_text("evidence")
            target = private / "aliases.json"
            target.symlink_to(outside)
            store = AliasStore(private, os.getuid())
            for action in [store.read, lambda: store.set(identity, "Name", inventory)]:
                with self.assertRaises((ValueError, OSError)):
                    action()
            self.assertEqual(outside.read_text(), "evidence")
            target.unlink()
            os.link(outside, target)
            with self.assertRaises((ValueError, OSError)):
                store.set(identity, "Name", inventory)
            self.assertEqual(outside.read_text(), "evidence")

    def test_native_alias_request_cannot_change_other_ids_or_acquire_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            (home / "Library/Application Support").mkdir(parents=True)
            data = home / "Library/Application Support/Gargoyl"
            inventory = normalize_inventory(response(), NOW)
            FleetCache(data, os.getuid()).write(inventory)
            identity = inventory["providers"][0]["id"]
            set_local_alias(
                home,
                dict(provider_id=identity, alias="Studio One"),
                NOW,
                owner=lambda: True,
            )
            event = alias_inventory(home, NOW)
            self.assertEqual(event["providers"][0]["alias"], "Studio One")
            for request in [
                dict(provider_id="wrong", alias="Name"),
                dict(provider_id=identity, alias="Name", restart=True),
            ]:
                with self.assertRaises(ValueError):
                    set_local_alias(home, request, NOW, owner=lambda: True)
            with self.assertRaises(ValueError):
                set_local_alias(
                    home,
                    dict(provider_id=identity, alias="Wrong"),
                    NOW,
                    owner=lambda: False,
                )
            self.assertEqual(
                AliasStore(data, os.getuid()).read(), {identity: "Studio One"}
            )

    def test_render_escapes_alias_and_keeps_public_export_separate(self):
        inventory = normalize_inventory(response(), NOW)
        identity = inventory["providers"][0]["id"]
        page = render_view(
            "fleet",
            None,
            None,
            inventory=inventory,
            aliases={identity: "<img src=x>"},
            now=NOW,
        )
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img", page)
        page = render_view(
            "fleet", None, None, inventory=inventory, aliases_available=False, now=NOW
        )
        self.assertIn("Local aliases unavailable", page)
        self.assertIn(identity, page)
