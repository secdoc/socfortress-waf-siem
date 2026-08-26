import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wazuh_waf_dashboard_gen.py"
spec = importlib.util.spec_from_file_location("wazuh_waf_dashboard_gen", MODULE_PATH)
assert spec is not None
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class WafDashboardTests(unittest.TestCase):
    def test_crs_context_panel_uses_indexed_matched_rule_descriptions(self):
        objects = module.build_objects()
        context = next(obj for obj in objects if obj["id"] == "waf_rule_context")
        state = json.loads(context["attributes"]["visState"])
        terms = next(agg for agg in state["aggs"] if agg["type"] == "terms")

        self.assertEqual(context["attributes"]["title"], "SOC WAF - CRS rule context (matched rule chain)")
        self.assertEqual(terms["params"]["field"], "data.waf_matched_rules")
        self.assertEqual(terms["params"]["customLabel"], "CRS rule ID and description")

    def test_crs_context_panel_has_a_full_width_dashboard_row(self):
        dashboard = module.build_dashboard("test-dashboard", "Test")
        panels = json.loads(dashboard["attributes"]["panelsJSON"])
        references = {ref["name"]: ref["id"] for ref in dashboard["references"]}
        context_panel = next(
            panel for panel in panels
            if references[panel["panelRefName"]] == "waf_rule_context"
        )

        self.assertEqual(context_panel["gridData"]["x"], 0)
        self.assertEqual(context_panel["gridData"]["w"], 48)


if __name__ == "__main__":
    unittest.main()
