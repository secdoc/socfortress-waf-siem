#!/usr/bin/env python3
"""
SOC Pipeline - SOCFortress WAF collector (Phase 5).

Read-only, incremental pull of Coraza/Caddy WAF request+blocking logs from the
SOCFortress WAF Management API, normalized to flat JSON events for the GELF
emitter (Graylog) and the Wazuh localfile (detection). Advances a high-water
mark so each run only ships NEW events.

AUTH (two-plane platform):
- The WAF has a management plane (this API, JWT) and a data plane (site bearer
  keys). Logs live on the MANAGEMENT plane. We POST /api/v1/auth/login with
  {email,password} -> access_token (JWT), then GET /api/v1/logs/ with
  Authorization: Bearer <jwt>. Site API keys (WAF_API_KEY) do NOT work here.

INCREMENTAL (API quirk, verified 2026-08-18):
- /api/v1/logs/ returns NEWEST-FIRST and honors ONLY limit/offset.
  start=/end= time filters are accepted but IGNORED by the server. So we paginate
  descending and STOP at the first event whose timestamp <= last high-water (or a
  transaction_id already delivered on the boundary), then reverse to ascending
  for delivery. Dedupe key: transaction_id.

READ-ONLY: only auth/login (POST creds) + logs GET. Never writes WAF config.

Env (/opt/data/.env): WAF_ADMIN_EMAIL, WAF_ADMIN_PASSWORD, WAF_BASE (optional,
default https://waf.example.local:8443).

Usage:
  waf_collector.py --out <dir> [--state <file>] [--max-pages N] [--page-size N]
                   [--dry-run] [--first-run-limit N]
"""
import argparse, hashlib, json, os, sys, ssl, datetime, urllib.request, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DEFAULT = os.path.join(HERE, ".waf_state.json")
DEFAULT_BASE = "https://waf.example.local:8443"

# The WAF UI presents a self-signed cert on first boot; API is on the same host.
# We pin verification OFF only for this internal DMZ host (documented risk).
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def load_env(path="/opt/data/.env"):
    e = {}
    if os.path.exists(path):
        for line in open(path):
            s = line.strip()
            if "=" in s and not s.startswith("#"):
                k, v = s.split("=", 1)
                e[k] = v
    return e


def _req(url, method="GET", token=None, body=None, timeout=25):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
        raw = r.read().decode("utf-8", "replace")
        return r.status, raw


def login(base, email, password):
    st, raw = _req(f"{base}/api/v1/auth/login", method="POST",
                   body={"email": email, "password": password})
    j = json.loads(raw)
    if j.get("requires_totp"):
        raise SystemExit("login requires TOTP; use a non-TOTP service account for the collector")
    tok = j.get("access_token")
    if not tok:
        raise SystemExit(f"login ok ({st}) but no access_token in response keys={list(j.keys())}")
    return tok


def fetch_page(base, token, limit, offset):
    q = urllib.parse.urlencode({"limit": limit, "offset": offset})
    st, raw = _req(f"{base}/api/v1/logs/?{q}", token=token)
    j = json.loads(raw)
    # API returns a bare list; tolerate a {items:[...]} wrapper too
    if isinstance(j, dict):
        for k in ("items", "logs", "results", "data"):
            if isinstance(j.get(k), list):
                return j[k]
        return []
    return j if isinstance(j, list) else []


def _flatten_matched(mr):
    """matched_rules: [{id,msg}, ...] -> compact 'id:msg; id:msg' string + id list."""
    if not isinstance(mr, list):
        return "", ""
    pairs, ids = [], []
    for m in mr:
        if isinstance(m, dict):
            rid = str(m.get("id", "")); msg = str(m.get("msg", ""))
            ids.append(rid)
            pairs.append(f"{rid}:{msg}"[:200])
    return "; ".join(pairs)[:1000], ",".join(ids)


def _cf_headers(ev):
    raw = ev.get("raw_log")
    if isinstance(raw, dict):
        return raw.get("transaction", {}).get("request", {}).get("headers", {}) or {}
    return {}


def _hdr(hdrs, key):
    v = hdrs.get(key)
    if isinstance(v, list) and v:
        return str(v[0]).strip()
    if isinstance(v, str):
        return v.split(",")[0].strip()
    return ""


def _true_source_ip(ev):
    """Extract the REAL client IP behind Cloudflare.

    The WAF sits behind Cloudflare, so ev['client_ip'] is the CF edge node, not the
    attacker. The true source is in the request headers cf-connecting-ip (primary)
    or x-forwarded-for (first hop). Falls back to client_ip if neither present
    (direct, non-CF traffic). This field is what you'd feed a blocklist / geo.
    """
    hdrs = _cf_headers(ev)
    for h in ("cf-connecting-ip", "true-client-ip", "x-forwarded-for"):
        val = _hdr(hdrs, h)
        if val:
            return val
    return ev.get("client_ip", "")


def _true_source_geo(ev):
    """Geo of the TRUE client, from Cloudflare's cf-ip* headers.

    Cloudflare geolocates the connecting client (the real attacker) and passes it in
    cf-ipcountry/cf-ipcity. The WAF's own geoip_* fields geolocate ev['client_ip'] =
    the CF EDGE node, which is wrong (e.g. a NL attacker tagged IT because it hit the
    Milan edge). Prefer the CF headers; fall back to the WAF geoip only for direct,
    non-CF traffic (where client_ip IS the true client, so its geoip is correct).
    Returns (country_code, country_name, city).
    """
    hdrs = _cf_headers(ev)
    cc = _hdr(hdrs, "cf-ipcountry")
    city = _hdr(hdrs, "cf-ipcity")
    if cc:
        # cf-ipcountry is an ISO code; there's no country-name header, so mirror the
        # code into the name field (kept for schema stability with the WAF fallback).
        return cc, cc, city
    return (ev.get("geoip_country_code", ""), ev.get("geoip_country_name", ""),
            ev.get("geoip_city", ""))


def stable_event_id(ev):
    identity = "\n".join(
        str(ev.get(key, ""))
        for key in (
            "id", "transaction_id", "timestamp", "site_id", "rule_id", "host", "uri"
        )
    )
    return hashlib.sha256(("socfortress-waf\n" + identity).encode()).hexdigest()


def normalize(ev):
    """One WAF log entry -> flat normalized event.

    ALL WAF-specific fields are namespaced 'waf_*' so the Wazuh indexer's reserved
    data.* object mappings (port/protocol/data/host...) can't collide and silently
    drop the doc. raw_log (nested dict) is kept only as a compact string for
    Graylog fidelity; it is NOT emitted as a nested object.
    """
    matched_str, matched_ids = _flatten_matched(ev.get("matched_rules"))
    raw = ev.get("raw_log")
    raw_str = json.dumps(raw, ensure_ascii=False)[:4000] if raw is not None else ""
    true_ip = _true_source_ip(ev)
    edge_ip = ev.get("client_ip", "")
    geo_cc, geo_country, geo_city = _true_source_geo(ev)
    return {
        "event_type": "waf_event",
        "source": "socfortress-waf",
        "waf_event_id": stable_event_id(ev),
        "timestamp": ev.get("timestamp", ""),
        "waf_id": ev.get("id", ""),
        "waf_txid": ev.get("transaction_id", ""),
        "waf_site_id": ev.get("site_id", ""),
        "waf_true_ip": true_ip,            # real attacker (behind Cloudflare) - use for blocklist/geo
        "waf_edge_ip": edge_ip,            # Cloudflare edge node that fronted the request
        "waf_client_ip": true_ip,          # keep waf_client_ip = the meaningful (true) IP for existing panels/rules
        "srcip": true_ip,                  # unified field: Wazuh manager GeoIP-enriches data.srcip -> GeoLocation.location (map)
        "waf_method": ev.get("method", ""),
        "waf_uri": (ev.get("uri", "") or "")[:1024],
        "waf_host": ev.get("host", ""),
        "waf_rule_id": str(ev.get("rule_id", "")),
        "waf_action": ev.get("action", ""),
        "waf_severity": (ev.get("severity", "") or ""),
        "waf_anomaly_score": ev.get("anomaly_score") if ev.get("anomaly_score") is not None else 0,
        "waf_matched_rules": matched_str,
        "waf_matched_ids": matched_ids,
        "waf_geo_cc": geo_cc,
        "waf_geo_country": geo_country,
        "waf_geo_city": geo_city,
        "waf_raw": raw_str,
    }


def load_state(path):
    if os.path.exists(path):
        try:
            return json.load(open(path))
        except Exception:
            pass
    return {"high_water": "", "boundary_txids": []}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="dir to write <ts>.jsonl (omit for dry-run preview)")
    ap.add_argument("--state", default=STATE_DEFAULT)
    ap.add_argument("--page-size", type=int, default=100)
    ap.add_argument("--max-pages", type=int, default=50)
    ap.add_argument("--first-run-limit", type=int, default=500,
                    help="on first run (no state), cap how far back to seed")
    ap.add_argument("--dry-run", action="store_true",
                    help="pull+normalize+sample; do NOT advance state or write output")
    args = ap.parse_args()

    env = load_env()
    base = env.get("WAF_BASE", DEFAULT_BASE).rstrip("/")
    email, pw = env.get("WAF_ADMIN_EMAIL"), env.get("WAF_ADMIN_PASSWORD")
    if not email or not pw:
        print("ERROR: WAF_ADMIN_EMAIL / WAF_ADMIN_PASSWORD not in /opt/data/.env"); sys.exit(1)

    state = load_state(args.state)
    hw = state.get("high_water", "")
    seen_boundary = set(state.get("boundary_txids", []))
    first_run = not hw

    token = login(base, email, pw)

    collected, stop = [], False
    for page in range(args.max_pages):
        offset = page * args.page_size
        rows = fetch_page(base, token, args.page_size, offset)
        if not rows:
            break
        for ev in rows:
            ts = ev.get("timestamp", "")
            txid = ev.get("transaction_id", "")
            if first_run:
                if len(collected) >= args.first_run_limit:
                    stop = True; break
            else:
                # stop once we reach events at/older than last high-water (or already delivered)
                if ts and hw and ts <= hw:
                    stop = True; break
                if txid and txid in seen_boundary:
                    stop = True; break
            collected.append(ev)
        if stop or len(rows) < args.page_size:
            break

    # collected is newest-first; deliver oldest-first
    collected.reverse()
    norm = [normalize(e) for e in collected]

    print(f"collected {len(norm)} new WAF events "
          f"(first_run={first_run}, high_water={hw or 'none'})")

    if args.dry_run:
        print("--- dry-run sample (up to 3 normalized events, values shown) ---")
        for e in norm[:3]:
            print(json.dumps(e, ensure_ascii=False, indent=2))
        # blocked/action histogram so we see the signal mix
        hist = {}
        for e in norm:
            hist[e["waf_action"]] = hist.get(e["waf_action"], 0) + 1
        print("action histogram:", json.dumps(hist))
        print("dry-run: state NOT advanced, nothing delivered")
        return

    if not norm:
        print("no new events; state unchanged"); return

    # write output + advance state
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        fp = os.path.join(args.out, f"waf-{stamp}.jsonl")
        with open(fp, "w") as f:
            for e in norm:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"wrote {len(norm)} events -> {fp}")

    newest_ts = max((e["timestamp"] for e in norm if e["timestamp"]), default=hw)
    boundary = [e["waf_txid"] for e in norm if e["timestamp"] == newest_ts and e["waf_txid"]]
    json.dump({"high_water": newest_ts, "boundary_txids": boundary},
              open(args.state, "w"), indent=2)
    print(f"state advanced: high_water={newest_ts}")


if __name__ == "__main__":
    main()
