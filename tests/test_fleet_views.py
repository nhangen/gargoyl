import copy
import unittest

from test_fleet_state import NOW, response

from gargoyl.fleet_state import normalize_inventory, provider_key
from gargoyl.native_views import render_view


class FleetViewTests(unittest.TestCase):
    def page(self, inventory=None, view="fleet", now=NOW):
        return render_view(
            view,
            None,
            None,
            inventory=inventory,
            local_alias="Fixture local alias",
            now=now,
        )

    def test_disconnected_is_not_zero_or_synthetic_and_local_is_separate(self):
        page = self.page()
        self.assertIn("not an empty fleet result", page)
        self.assertIn("Other machines have not been queried", page)
        self.assertIn("local alias, not a provider name or ID", page)
        self.assertNotIn("00000000-0000-4000-8000-000000000001", page)
        self.assertNotIn("Fixture Mac", page)

    def test_actual_ids_filters_details_and_provenance(self):
        value = normalize_inventory(response(), NOW)
        page = self.page(value)
        self.assertLess(
            page.index("Owned provider inventory"), page.index("This Mac ·")
        )
        self.assertIn("provider-real-format-test-only", page)
        self.assertIn("source_name", page)
        self.assertIn("not independent remote process verification", page)
        detail = "fleet-node-" + provider_key(value["providers"][0]["id"])
        self.assertIn("gargoyl-view://" + detail + "/", page)
        self.assertIn("Actual provider ID", self.page(value, detail))
        self.assertIn("No records match this filter", self.page(value, "fleet-older"))
        self.assertIn("Fixture Mac", self.page(value, "fleet-recent"))
        self.assertNotIn("must-never-persist", page)
        for unsafe in (
            "<form",
            "<script",
            "token=",
            'href="https:',
            "restart-provider",
        ):
            self.assertNotIn(unsafe, page)

    def test_stale_partial_and_disconnected_never_claim_current_health(self):
        value = normalize_inventory(response(), NOW)
        value["partial"] = True
        value["connection"] = "disconnected"
        page = self.page(value, now="2026-11-02T00:00:00Z")
        self.assertIn("Partial inventory", page)
        self.assertIn("cached records", page)
        self.assertIn("stale", page)
        self.assertIn("unknown — no fresh unique account identity match", page)
        self.assertNotIn("healthy", page.replace("absent or healthy", ""))

    def test_visible_section_navigation_has_real_targets_in_each_surface(self):
        from html.parser import HTMLParser

        class Links(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = set()
                self.fragments = []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if "id" in attrs:
                    self.ids.add(attrs["id"])
                href = attrs.get("href", "")
                if href.startswith("about:blank#"):
                    self.fragments.append(href.split("#", 1)[1])

        value = normalize_inventory(response(), NOW)
        for inventory, view in [
            (None, "fleet"),
            (value, "fleet"),
            (value, "fleet-node-" + provider_key(value["providers"][0]["id"])),
        ]:
            page = Links()
            page.feed(self.page(inventory, view))
            self.assertTrue(set(page.fragments) <= page.ids)
            self.assertTrue({"fleet-overview", "needs-attention"} <= page.ids)

    def test_source_text_is_escaped_and_absent_id_is_not_substituted(self):
        raw = response()
        raw["providers"][0]["name"] = "<img src=x onerror=alert(1)>"
        value = normalize_inventory(raw, NOW)
        page = self.page(value)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img", page)
        unknown = "fleet-node-" + "0" * 64
        self.assertIn("No substitute was selected", self.page(value, unknown))
        bad = copy.deepcopy(value)
        bad["providers"][0]["secret"] = "private"
        with self.assertRaises(ValueError):
            self.page(bad)
