import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wazuh_waf_dashboard_gen.py"
spec = importlib.util.spec_from_file_location("wazuh_waf_dashboard_gen", MODULE_PATH)
assert spec is not None
generator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(generator)


class WafDashboardTests(unittest.TestCase):
    def test_crs_context_panel_uses_indexed_matched_rule_descriptions(self):
        objects = generator.build_objects()
        context = next(obj for obj in objects if obj["id"] == "waf_rule_context")
        state = json.loads(context["attributes"]["visState"])

        self.assertEqual(context["attributes"]["title"], "SOC WAF - CRS rule context (matched rule chain)")
        terms = next(agg for agg in state["aggs"] if agg["type"] == "terms")
        self.assertEqual(terms["params"]["field"], "data.waf_matched_rules")
        self.assertEqual(terms["params"]["customLabel"], "CRS rule ID and description")

    def test_crs_context_panel_has_a_full_width_dashboard_row(self):
        dashboard = generator.build_dashboard("test-dashboard", "Test")
        panels = json.loads(dashboard["attributes"]["panelsJSON"])
        references = {ref["name"]: ref["id"] for ref in dashboard["references"]}
        context_panel = next(
            panel for panel in panels
            if references[panel["panelRefName"]] == "waf_rule_context"
        )

        self.assertEqual(context_panel["gridData"]["x"], 0)
        self.assertEqual(context_panel["gridData"]["w"], 48)

    def test_enterprise_dashboard_tracks_unique_stable_waf_events(self):
        objects = generator.build_objects()
        unique = next(obj for obj in objects if obj["id"] == "waf_kpi_unique")
        state = json.loads(unique["attributes"]["visState"])
        metric = next(agg for agg in state["aggs"] if agg["type"] == "cardinality")
        self.assertEqual(metric["params"]["field"], "data.waf_event_id")

        dashboard = generator.build_dashboard("test-dashboard", "Test")
        self.assertIn("enterprise target", dashboard["attributes"]["description"])
        panels = json.loads(dashboard["attributes"]["panelsJSON"])
        widths = {}
        for panel in panels:
            widths.setdefault(panel["gridData"]["y"], 0)
            widths[panel["gridData"]["y"]] += panel["gridData"]["w"]
        self.assertTrue(all(width == 48 for width in widths.values()))


if __name__ == "__main__":
    unittest.main()
