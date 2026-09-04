# How-To: Ship SOCFortress WAF logs to Graylog + Wazuh

*Phase 5. Source of truth: `private implementation repository`. Last verified live: 2026-08-26.*

Wires the SOCFortress WAF (Caddy + Coraza / OWASP CRS v4) request+blocking logs into the SOC
pipeline the standard way: one read-only collector pulls the WAF management API, normalizes each
event, and delivers to BOTH Graylog (retention/hunting, full volume) and Wazuh (detection,
rule-gated). Follows the same parallel-consumer pattern as the DNS and Greenbone feeds.

## Auth: two planes (the thing that cost the most time)

The WAF platform has **two separate auth planes**. Getting logs requires the management plane.

- **Management plane** (admin API, JWT): `POST /api/v1/auth/login` with JSON `{"email","password"}`
  returns `access_token` (JWT, ~269 chars). Send it as `Authorization: Bearer <jwt>` on
  `/api/v1/logs/`. This is where the logs live.
- **Data plane** (site bearer keys, the "API Keys" screen in the UI): these authorize a client to
  pass *through* the WAF to a site that has API-key auth enabled. They return
  `{"detail":"Invalid or expired token"}` on the management API. **`WAF_API_KEY` does NOT pull logs.**

Use a dedicated **non-TOTP service account** for the collector (`requires_totp:false` in the login
response, or the non-interactive login can't complete). Read-only/viewer role if the platform offers
one.

## API quirks (verified, drove the collector design)

- `/api/v1/logs/` returns **newest-first** and honors **only `limit`/`offset`**. The `start=`/`end=`
  time filters are accepted but **silently ignored**. So incremental pull is descending pagination
  that stops at the high-water mark, not a server-side time filter.
- `id` is a UUID (not monotonic), so the high-water key is `timestamp`; `transaction_id` is the
  dedupe/boundary key.
- The platform leaves `anomaly_score` = 0 and carries `severity` as a **string** (CRITICAL/…), so
  severity bucketing keys on the string, never the numeric score.
- Nginx on :8443 serves the React SPA and returns `index.html` (HTTP 200) for unknown paths, so a
  200 is not proof an API path exists. The real API is under `/api/v1/*`.

## Components

| File (repo) | Role |
|-------------|------|
| `collector/waf_collector.py` | Read-only incremental pull + normalize. Login → paginate descending → stop at high-water → normalize to flat JSON. `--dry-run` reads+samples without advancing state. |
| `collector/waf_pipeline.py` | Runner: calls the collector, then fans out NEW events to Graylog (GELF/TCP) + Wazuh localfile. |
| `wazuh/waf_rules.xml` | Detection rules (ID range 117000-117999). |
| `scripts/waf-pull.sh` | Cron-safe wrapper; one-line JSON status to `/var/log/waf-pull.log`. |

## Normalization (reserved-field guard + true source IP)

Every WAF-specific field is namespaced `waf_*` (`waf_client_ip`, `waf_rule_id`, `waf_uri`,
`waf_host`, `waf_action`, `waf_severity`, `waf_matched_ids`, `waf_geo_cc`, …). This avoids the
Wazuh indexer's reserved `data.*` object mappings (port/protocol/data/host) that otherwise trigger a
`mapper_parsing_exception` and **silently drop the whole doc**. `matched_rules` (list of {id,msg}) is
flattened to a string + id list; the full nested Coraza `raw_log` is kept only as a compact string
(`waf_raw`) for Graylog fidelity and is **dropped from the Wazuh copy** (detection doesn't need it).

**True source IP (Cloudflare):** the WAF is Cloudflare-fronted, so the API's `client_ip` is the CF
edge node, NOT the attacker. The collector extracts the real client from the request headers
(`cf-connecting-ip` → `true-client-ip` → `x-forwarded-for`, first hop) into **`waf_true_ip`**, keeps
the CF node in **`waf_edge_ip`**, and sets **`waf_client_ip` = the true IP** so rules and dashboards
key on the meaningful value. Consequences:
- The frequency/anti-flood rules (117100/117101, keyed on `waf_client_ip`) now correctly group by
  attacker, not by CF edge (which would have collapsed all attackers behind one node).
- Any blocklist/geo use `waf_true_ip`. **Never** aggregate on `waf_edge_ip` for "top sources" — it
  charts Cloudflare, not attackers.
- GeoIP fields (`waf_geo_*`) come from the WAF/MaxMind lookup, which on CF-fronted traffic reflects
  the CF edge; treat country/city as approximate until/unless re-derived from `waf_true_ip`.

## Delivery

- **Graylog:** GELF/TCP input "SOC Pipeline - WAF GELF TCP" on **:12203** (12201=vuln, 12202=DNS).
  Full volume. Severity string → GELF level (CRITICAL=2, ERROR/HIGH=3, WARNING/MEDIUM=4, else 6).
- **Wazuh:** normalized JSON-lines appended over SSH to the manager localfile
  `/var/ossec/logs/waf/events.jsonl` (`<log_format>json</log_format>`), read by the built-in json
  decoder. No custom decoder.

For HA or segmented targets, use `--graylog-endpoint NAME=HOST:PORT:https` with `--graylog-ca` for per-event HTTP acknowledgement, and `--wazuh-endpoint NAME=HOST:PORT:tcp` for newline-delimited JSON. Add `--no-default-graylog` and `--no-default-wazuh` after target acceptance. Source state is committed only after every configured consumer succeeds.

**GELF/TCP note:** the sender sets `SO_LINGER` + `shutdown(SHUT_WR)` then waits for peer close, so a
batch fully drains before `close()`. **Search gotcha:** GELF messages carry the *event* timestamp,
so Graylog stores them at event time. When verifying, widen the search range (events can be hours
old) or you will see 0 results for messages that landed fine.

## Wazuh alert discipline (anti-flood)

Rule IDs 117000-117999. Chained under stock rule 86600 (which else swallows generic JSON).

| Rule | Level | Fires on |
|------|-------|----------|
| 117000 | 0 | base: any WAF event (recorded, not alerted) |
| 117010 | 5 | a single CRITICAL block (queryable, no page) |
| 117011 | 3 | any other single block |
| 117012 | 2 | detected-only (site in detection mode) |
| 117100 | 10 | **10+ blocks from one source IP in 120s** (page) |
| 117101 | 12 | **5+ CRITICAL blocks from one source IP in 120s** (page) |

Single blocks stay low (internet-facing WAFs see constant scanner noise); only a source IP crossing
a rate threshold pages. Thresholds are starting points — tune against baseline.

## Deploy / validate (change-controlled)

1. Graylog input: create GELF/TCP on 12203 (copy an existing input's config; `global:true`).
2. Wazuh (offline-validate before restart):
   - `scp wazuh/waf_rules.xml` → `/var/ossec/etc/rules/` (the SSH service account is in the wazuh group; dir is group-writable).
   - Add one `<localfile>` block for `/var/ossec/logs/waf/events.jsonl` to `ossec.conf`. **Pitfall:**
     `ossec.conf` has TWO `<ossec_config>` sections; a naive replace-on-`</ossec_config>` inserts the
     block twice (double ingest). Insert before the FIRST close only, then verify the count is 1.
   - `sudo wazuh-analysisd -t` (RC 0), then `wazuh-logtest` a real event (expect rule 117010), then
     `sudo systemctl restart wazuh-manager`.
3. Seed high-water to now (`collector/.waf_state.json`) so the first cron run doesn't backfill history.
4. Register cron: `*/15 * * * *`, script `waf-pull.sh` (job <CRON_JOB_ID>).

## Dashboard (Wazuh / OpenSearch Dashboards)

`scripts/wazuh_waf_dashboard_gen.py` generates a saved-objects NDJSON for the
"SOC Pipeline - WAF (Enterprise Target)" dashboard over `wazuh-alerts-*`
(`rule.groups: waf`). The dashboard includes a distinct stable-event KPI on `data.waf_event_id`. All `data.waf_*` fields are keyword-mapped, so they aggregate directly (no
`.keyword` suffix). Panels: total + blocked KPIs, severity-tier donut (rule.level), action split,
**top attacking source IPs (data.waf_true_ip — the real client, not the CF edge)**, top primary
CRS rule IDs, a full-width **CRS rule context** panel on `data.waf_matched_rules` showing matched
IDs and descriptions, top targeted hosts, top targeted URIs, attacks by country, and a timeline
split by tier. The ID panel is the stable counting dimension; the matched-rule chain explains the
detection and preserves multi-rule context.

Generate + import (dashboard API on :443, not :9200):
```
python3 scripts/wazuh_waf_dashboard_gen.py --index-pattern-id 'wazuh-alerts-*' \
    --out docs/wazuh-waf-dashboard.ndjson
curl -sk -u "$WAZUH_IDX_USER:$WAZUH_IDX_PASS" -X POST \
    "https://<WAZUH_INDEXER>/api/saved_objects/_import?overwrite=true" \
    -H "osd-xsrf: true" --form file=@docs/wazuh-waf-dashboard.ndjson
```
**Grid pitfall:** OpenSearch Dashboards uses a 48-column responsive grid; every row's panel widths
MUST sum to 48 or the remainder renders as empty space. The generator `assert`s this per row.

## Verify

- Graylog: `source:socfortress-waf` (widen range to 7d). Expect `waf_action`, `waf_true_ip`,
  `waf_severity`, `waf_rule_id` populated.
- Wazuh indexer: `rule.id:[117000 TO 117999]` — CRITICAL blocks show as 117010/level 5.
- Dashboard: aggregations on `data.waf_true_ip` chart real attacker IPs (CF edges appear only under
  `data.waf_edge_ip`). The CRS context panel aggregates `data.waf_matched_rules` so analysts see
  labels such as `930130:Restricted File Access Attempt` instead of only numeric IDs.
- Cron: `/var/log/waf-pull.log` one-line JSON per run.

## Related

- [SOCFortress WAF Platform](/infrastructure/socfortress-waf) — the platform + two-plane auth.
- [SOC Pipeline architecture](/siem/soc-pipeline/architecture)
- [How-To: GELF emitter](/siem/soc-pipeline/how-to/gelf-emitter) · [Wazuh vuln rules](/siem/soc-pipeline/how-to/wazuh-vuln-rules)
