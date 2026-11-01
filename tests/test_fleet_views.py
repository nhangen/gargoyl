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
        self.assertIn("Source name", page)
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


class FleetLayoutTests(unittest.TestCase):
    def inventory(self):
        raw = response()
        twin = copy.deepcopy(raw["providers"][0])
        twin["id"] = "provider-second-test-only"
        twin["status"] = "offline"
        twin["last_heartbeat"] = "not-a-time"
        raw["providers"].append(twin)
        raw["total_count"] = 3
        return normalize_inventory(raw, NOW)

    def page(self, view="fleet", **kwargs):
        return render_view(view, None, None, inventory=self.inventory(), now=NOW, **kwargs)

    def test_full_ids_duplicates_reasons_and_freshness_in_rows(self):
        page = self.page()
        self.assertIn('<span class="fleet-id">provider-real-format-test-only</span>', page)
        self.assertIn('<span class="fleet-id">provider-second-test-only</span>', page)
        self.assertEqual(page.count("Same label as another record"), 2)
        self.assertIn("Invalid timestamp", page)
        self.assertIn("report current", page)
        self.assertIn('<span class="adv">offline</span>', page)
        self.assertNotIn('<span class="adv">running</span>', page)
        self.assertIn("2 of 3 reported records", page)
        self.assertIn("recent · 0 s before read", page)

    def test_filters_show_counts_and_current_page(self):
        page = self.page("fleet-unknown")
        self.assertIn('href="gargoyl-view://fleet-unknown/" aria-current="page">Unknown heartbeat <span class="n">1</span>', page)
        self.assertIn('Recent heartbeat <span class="n">1</span>', page)
        self.assertIn("provider-second-test-only", page)
        self.assertNotIn('<span class="fleet-id">provider-real-format-test-only</span>', page)

    def test_alias_removes_duplicate_flag_and_keeps_label_source(self):
        page = self.page(aliases={"provider-second-test-only": "Studio Two"})
        self.assertNotIn("Same label as another record", page)
        self.assertIn("Local alias · source name “Fixture Mac”", page)


class FleetSafetyTests(unittest.TestCase):
    def test_untrusted_cells_are_escaped(self):
        raw = response()
        provider = raw["providers"][0]
        provider["id"] = "<i>id"
        provider["status"] = "<i>status"
        provider["version"] = "<i>version"
        value = normalize_inventory(raw, NOW)
        page = render_view("fleet", None, None, inventory=value, now=NOW, local_alias="<i>mac")
        self.assertNotIn("<i>", page)
        self.assertIn("&lt;i&gt;status", page)

    def test_heartbeat_after_read_and_age_boundaries(self):
        from gargoyl.fleet_views import _age

        self.assertEqual([_age(v) for v in (119, 120, 7199, 7200, 172799, 172800)],
                         ["119 s", "2 min", "119 min", "2 h", "47 h", "2 days"])
        raw = response()
        raw["providers"][0]["last_heartbeat"] = "2026-11-01T00:00:30Z"
        value = normalize_inventory(raw, NOW)
        page = render_view("fleet", None, None, inventory=value, now="2026-11-01T00:01:00Z")
        self.assertNotIn("before read", page)

    def test_local_evidence_states_freshness_in_words(self):
        from test_dashboard import snapshot

        old = snapshot(source="host", at="2026-01-01T00:00:00Z")
        page = render_view("fleet", dict(evaluated_at=NOW, snapshots=[old]), None, now=NOW)
        self.assertIn("stale · host", page)
