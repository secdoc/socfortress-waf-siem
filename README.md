# socfortress-waf-siem

Wire a **[SOCFortress WAF Management Platform](https://github.com/socfortress/waf-platform-public)**
(Caddy + Coraza / OWASP Core Rule Set) into a SIEM as a first-class detection lane: a
read-only collector pulls the WAF's request/blocking logs, normalizes them, and delivers
to **both Graylog** (retention/hunting, full volume) and **Wazuh** (detection, rule-gated),
plus a ready-to-import **Wazuh/OpenSearch dashboard** with CRS rule IDs and matched-rule descriptions.

> Sanitized, adaptable reference. Placeholders (`<WAF_HOST>`, `<GRAYLOG_HOST>`,
> `<WAZUH_HOST>`, RFC5737 example networks) stand in for real values, so you can drop in
> your own environment. Carries no real environment data. Companion to the broader
> [soc-pipeline](https://github.com/secdoc/soc-pipeline-public) build and its siblings
> [greenbone-wazuh-graylog](https://github.com/secdoc/greenbone-wazuh-graylog) and
> [technitium-wazuh-graylog](https://github.com/secdoc/technitium-wazuh-graylog).

## Why this exists

A WAF that only logs to its own console is a silo. This turns the WAF into one source in
your existing pipeline: the same `log -> event -> alert -> incident` path as every other
feed, correlated in the SIEM you already run. Graylog keeps the full volume for hunting;
Wazuh gets a rule-gated subset for detection so a busy WAF can't flood the pager.

## Architecture (parallel consumers, not a chain)

```
  SOCFortress WAF  --(management API, JWT)-->  collector (read-only, incremental)
                                                   |  normalize once
                        +--------------------------+--------------------------+
                        v                                                     v
             Graylog (GELF/TCP)                                  Wazuh manager localfile
             retention + hunting                                 detection (rules 117xxx)
             full volume                                         single=low, freq/IP=page
```

Do **not** chain source -> Graylog -> Wazuh: Graylog reformats and breaks Wazuh decoders.
Both consumers get the normalized event independently.

## Two things this project gets right (the hard-won bits)

1. **Two-plane auth.** The WAF has a management plane (admin API, **JWT** via
   `POST /api/v1/auth/login`) and a data plane (site "API Keys" — bearer keys clients present
   to pass *through* the WAF). **Logs live on the management plane.** The site API keys do NOT
   read logs. Use a dedicated **non-TOTP service account** for the collector.

2. **True client IP behind a CDN.** If the WAF sits behind Cloudflare, the API's `client_ip`
   is the **CDN edge**, not the attacker, and the WAF's own GeoIP geolocates the edge (a NL
   attacker shows as IT because it hit the Milan edge). The collector extracts the real client
   from `cf-connecting-ip` into `waf_true_ip` and derives geo from `cf-ipcountry`/`cf-ipcity`.
   Aggregate "top sources" and geo on `waf_true_ip` / `waf_geo_*`, **never** on `waf_edge_ip`.

## Fields (normalized, Wazuh-safe)

All WAF fields are namespaced `waf_*` so they don't collide with the Wazuh indexer's reserved
`data.*` object mappings (which would silently drop the whole doc). Key fields: `waf_true_ip`,
`waf_edge_ip`, `waf_rule_id` (CRS id), `waf_action`, `waf_severity`, `waf_matched_rules`, `waf_matched_ids`,
`waf_host`, `waf_uri`, `waf_geo_cc/country/city`, and stable SHA-256 `waf_event_id`. See `samples/waf-events-sample.jsonl`.

The pipeline writes source progress to a candidate state and atomically promotes it only after every configured consumer succeeds. It supports legacy GELF/TCP and Wazuh localfile delivery, plus acknowledged Graylog GELF HTTP over HTTPS and newline-delimited Wazuh TCP endpoints.

## Detection rules (Wazuh, `wazuh/rules/waf_rules.xml`)

Rule IDs `117000-117999`, chained under stock rule 86600. Anti-flood discipline: single blocks
stay low-level (queryable, no page); only a source IP crossing a rate threshold pages.

| Rule | Level | Fires on |
|------|-------|----------|
| 117000 | 0 | base: any WAF event (recorded) |
| 117010 | 5 | single CRITICAL block |
| 117011 | 3 | any other single block |
| 117012 | 2 | detected-only (detection mode) |
| 117100 | 10 | 10+ blocks from one source IP in 120s |
| 117101 | 12 | 5+ CRITICAL blocks from one source IP in 120s |

## Dashboard (`scripts/wazuh_waf_dashboard_gen.py`)

Generates an OpenSearch Dashboards saved-objects NDJSON (also prebuilt at
`docs/wazuh-waf-dashboard.ndjson`): total and distinct-stable-event KPIs, severity/action donuts, **top attacking source IPs
(true client)**, top primary CRS rule IDs, a full-width matched-rule context panel with CRS IDs and
descriptions, targeted hosts/URIs, attacks by country, and a timeline.

## Quick start

```bash
cp .env.example .env      # fill in WAF_*, GRAYLOG_HOST, WAZUH_* (never commit real .env)
python3 collector/waf_pipeline.py --dry-run          # login + pull + normalize, no delivery
python3 collector/waf_pipeline.py                    # deliver new events to Graylog + Wazuh
python3 collector/waf_pipeline.py \
  --graylog-endpoint target=graylog.example.local:12215:https --graylog-ca ./ca.pem \
  --wazuh-endpoint target=wazuh.example.local:5514:tcp --no-default-graylog --no-default-wazuh
python3 scripts/wazuh_waf_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' \
    --out docs/wazuh-waf-dashboard.ndjson            # regenerate the dashboard NDJSON
```

Deploy the collector as a 15-minute cron (incremental high-water state means each run ships
only new events). Full walkthrough with auth, API quirks, Wazuh install/validate, and the
dashboard import in [`docs/how-to-waf-feed.md`](docs/how-to-waf-feed.md).

## Repo layout

```
collector/   waf_collector.py (pull+normalize), waf_pipeline.py (fan-out to Graylog+Wazuh)
wazuh/rules/ waf_rules.xml (117xxx detection + anti-flood frequency rules)
scripts/     wazuh_waf_dashboard_gen.py (dashboard-as-code), scrub_check.py (public gate)
tests/       dashboard generator regression tests
docs/        how-to-waf-feed.md, SANITIZATION.md, wazuh-waf-dashboard.ndjson
samples/     waf-events-sample.jsonl (SYNTHETIC)
```

## License

Dual-licensed: code under Apache-2.0 (`LICENSE`), docs/diagrams under CC BY 4.0
(`LICENSE-docs`). Attribution required under both. See `LICENSING.md` and `NOTICE`.

*Not affiliated with SOCFortress; this integrates with their public WAF platform.*
