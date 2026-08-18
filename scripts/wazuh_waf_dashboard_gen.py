#!/usr/bin/env python3
"""
SOC Pipeline - Wazuh (OpenSearch Dashboards) WAF dashboard builder.

Emits an OpenSearch Dashboards saved-objects NDJSON for import into the Wazuh
dashboard. Builds "SOC Pipeline - WAF (SOCFortress/Coraza)" over the existing
`wazuh-alerts-*` index pattern, filtered to `rule.groups: waf`.

Panels (aggregation-based, no scripted fields; all data.waf_* are keyword-mapped
so they aggregate directly):
  - KPI: total WAF alerts
  - KPI: blocked count (rule.groups: web_attack AND data.waf_action: blocked)
  - Severity tier: donut on rule.level (2/3/5/10/12)
  - Action split: donut on data.waf_action (blocked/detected/passed)
  - Top attacking source IPs: bar on data.waf_true_ip  (TRUE client behind Cloudflare)
  - Top CRS rules: bar on data.waf_rule_id
  - Top targeted hosts: bar on data.waf_host
  - Top targeted URIs: bar on data.waf_uri
  - Attacks by country: bar on data.waf_geo_country
  - Alert timeline split by rule.level

IMPORTANT (honesty): source-IP + geo panels use data.waf_true_ip / data.waf_geo_*.
Because the WAF is Cloudflare-fronted, data.waf_edge_ip is the CF node, NOT the
attacker; the collector extracts the real client from cf-connecting-ip into
waf_true_ip (and mirrors it into waf_client_ip). NEVER build a "top sources" panel
on waf_edge_ip - it charts Cloudflare, not attackers.

Writes NOTHING to the cluster. Produces the NDJSON only; import is a separate step.

Usage:
  wazuh_waf_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' --out docs/wazuh-waf-dashboard.ndjson
"""
import argparse, json, os


def _vis(vid, title, vis_state, query="rule.groups: waf"):
    index_ref = "kibanaSavedObjectMeta.searchSourceJSON.index"
    ss = {"query": {"query": query, "language": "kuery"}, "filter": [], "indexRefName": index_ref}
    return {
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "visState": json.dumps(vis_state), "uiStateJSON": "{}",
            "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        "references": [{"name": index_ref, "type": "index-pattern", "id": "__IPID__"}],
    }


def _metric(vid, title, label, query="rule.groups: waf"):
    vs = {"title": title, "type": "metric",
          "params": {"metric": {"percentageMode": False, "useRanges": False,
                                "colorSchema": "Green to Red", "metricColorMode": "None",
                                "labels": {"show": True}, "style": {"fontSize": 48}}},
          "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                    "params": {"customLabel": label}}]}
    return _vis(vid, title, vs, query)


def _pie(vid, title, field, custom_label=None, size=10, query="rule.groups: waf"):
    vs = {"title": title, "type": "pie",
          "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                     "legendPosition": "right", "isDonut": True,
                     "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
          "aggs": [
              {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
              {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
               "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                          "customLabel": custom_label or field}}]}
    return _vis(vid, title, vs, query)


def _terms_bar(vid, title, field, size=15, custom_label=None, query="rule.groups: waf"):
    vs = {"title": title, "type": "histogram",
          "params": {"type": "histogram", "grid": {"categoryLines": False},
                     "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                                       "show": True, "style": {}, "scale": {"type": "linear"},
                                       "labels": {"show": True, "truncate": 100}, "title": {}}],
                     "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                    "position": "bottom", "show": True, "style": {},
                                    "scale": {"type": "linear", "mode": "normal"},
                                    "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                                    "title": {"text": "Count"}}],
                     "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                       "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                                       "drawLinesBetweenPoints": True, "showCircles": True}],
                     "addTooltip": True, "addLegend": True, "legendPosition": "right",
                     "times": [], "addTimeMarker": False},
          "aggs": [
              {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
              {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
               "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                          "otherBucket": False, "missingBucket": False,
                          "customLabel": custom_label or field}}]}
    return _vis(vid, title, vs, query)


def _timeline(vid, title, split_field, query="rule.groups: waf"):
    vs = {"title": title, "type": "histogram",
          "params": {"type": "histogram", "grid": {"categoryLines": False},
                     "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                       "show": True, "style": {}, "scale": {"type": "linear"},
                                       "labels": {"show": True, "truncate": 100}, "title": {}}],
                     "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                    "position": "left", "show": True, "style": {},
                                    "scale": {"type": "linear", "mode": "normal"},
                                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                    "title": {"text": "Count"}}],
                     "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                       "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                     "addTooltip": True, "addLegend": True, "legendPosition": "right",
                     "times": [], "addTimeMarker": False},
          "aggs": [
              {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
              {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
               "params": {"field": "timestamp", "useNormalizedEsInterval": True, "interval": "auto",
                          "drop_partials": False, "min_doc_count": 1}},
              {"id": "3", "enabled": True, "type": "terms", "schema": "group",
               "params": {"field": split_field, "orderBy": "1", "order": "desc", "size": 5,
                          "customLabel": "severity tier (rule.level)"}}]}
    return _vis(vid, title, vs, query)


def build_objects():
    objs = [
        _metric("waf_kpi_total", "SOC WAF - Total WAF alerts", "WAF alerts"),
        _metric("waf_kpi_blocked", "SOC WAF - Blocked requests", "blocked",
                query="rule.groups: waf AND data.waf_action: blocked"),
        _pie("waf_sev_tier", "SOC WAF - Severity tier (rule.level)", "rule.level", "tier"),
        _pie("waf_action", "SOC WAF - Action split", "data.waf_action", "action"),
        _terms_bar("waf_top_src", "SOC WAF - Top attacking source IPs (true client)",
                   "data.waf_true_ip", 15, "source IP"),
        _terms_bar("waf_top_rules", "SOC WAF - Top CRS rules", "data.waf_rule_id", 15, "CRS rule"),
        _terms_bar("waf_top_hosts", "SOC WAF - Top targeted hosts", "data.waf_host", 12, "host"),
        _terms_bar("waf_top_uris", "SOC WAF - Top targeted URIs", "data.waf_uri", 15, "URI"),
        _terms_bar("waf_by_country", "SOC WAF - Attacks by country", "data.waf_geo_country", 12, "country"),
        _timeline("waf_timeline", "SOC WAF - Alert timeline by tier", "rule.level"),
    ]
    return objs


def build_dashboard(dash_id, title):
    GRID_W = 48
    sizes = {
        "waf_kpi_total": 8, "waf_kpi_blocked": 8, "waf_sev_tier": 8, "waf_action": 8,
        "waf_top_src": 12, "waf_top_rules": 12, "waf_top_hosts": 10, "waf_top_uris": 10,
        "waf_by_country": 10, "waf_timeline": 10,
    }
    rows = [
        [("waf_kpi_total", 12), ("waf_kpi_blocked", 12), ("waf_sev_tier", 12), ("waf_action", 12)],  # 48
        [("waf_top_src", 24), ("waf_top_rules", 24)],   # 48
        [("waf_top_hosts", 24), ("waf_top_uris", 24)],  # 48
        [("waf_by_country", 48)],                        # 48
        [("waf_timeline", 48)],                          # 48
    ]
    panels_json, refs = [], []
    cur_y, n = 0, 0
    for group in rows:
        assert sum(w for _, w in group) == GRID_W, f"row does not fill 48 cols: {group}"
        cur_x, max_h = 0, 0
        for pid, w in group:
            h = sizes[pid]
            pref = f"panel_{n}"
            panels_json.append({"version": "2.13.0",
                                "gridData": {"x": cur_x, "y": cur_y, "w": w, "h": h, "i": str(n)},
                                "panelIndex": str(n), "embeddableConfig": {}, "panelRefName": pref})
            refs.append({"name": pref, "type": "visualization", "id": pid})
            cur_x += w; max_h = max(max_h, h); n += 1
        cur_y += max_h
    dash = {
        "id": dash_id, "type": "dashboard",
        "attributes": {
            "title": title, "hits": 0,
            "description": "SOCFortress WAF (Coraza/OWASP CRS) posture over wazuh-alerts-* "
                           "(rule.groups: waf). Source IP/geo use the TRUE client (behind "
                           "Cloudflare), not the CF edge. Built by scripts/wazuh_waf_dashboard_gen.py.",
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-7d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "rule.groups: waf", "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    }
    return dash


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index-pattern-id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dashboard-id", default="soc-pipeline-waf-socfortress")
    ap.add_argument("--title", default="SOC Pipeline - WAF (SOCFortress/Coraza)")
    args = ap.parse_args()

    objs = build_objects()
    for o in objs:
        for r in o["references"]:
            if r["type"] == "index-pattern":
                r["id"] = args.index_pattern_id
    dash = build_dashboard(args.dashboard_id, args.title)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for o in objs + [dash]:
            f.write(json.dumps(o) + "\n")
    print(f"wrote {args.out} ({len(objs)} visualizations + 1 dashboard)")
    print("import with: POST /api/saved_objects/_import?overwrite=true "
          "(multipart file=@<ndjson>, header osd-xsrf: true)")


if __name__ == "__main__":
    main()
