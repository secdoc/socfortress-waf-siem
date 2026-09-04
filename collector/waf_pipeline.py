#!/usr/bin/env python3
"""
SOC Pipeline - SOCFortress WAF pipeline runner (Phase 5).

One cycle:
  1. collector: read-only incremental pull from the WAF management API
     (waf_collector.py), writing normalized WAF events + advancing high-water.
  2. deliver each NEW event to BOTH consumers (parallel-consumer model):
       - GELF/TCP -> Graylog WAF input (retention/hunting, full volume)
       - append to the Wazuh manager WAF localfile (detection, rule-gated)

Dedupe/incremental handled by the collector (high-water + transaction_id
boundary). Read-only against the WAF. Safe to cron (15 min).

The environment file path is configurable with `WAF_ENV_FILE`; the default is `~/.config/soc-pipeline/waf.env`.
"""
import argparse, http.client, json, os, shutil, socket, ssl, struct, subprocess, sys, tempfile, time
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env(path=None):
    path = path or os.environ.get(
        "WAF_ENV_FILE", os.path.expanduser("~/.config/soc-pipeline/waf.env")
    )
    e = {}
    if os.path.exists(path):
        for l in open(path):
            if "=" in l and not l.strip().startswith("#"):
                k, v = l.strip().split("=", 1); e[k] = v
    return e


def parse_endpoint(value):
    name, separator, address = value.partition("=")
    if not separator or not name or not address:
        raise ValueError("Endpoint must be NAME=HOST:PORT[:tcp|https]")
    parts = address.rsplit(":", 2)
    transport = parts[-1].lower() if len(parts) == 3 else "tcp"
    if len(parts) == 3 and transport in ("tcp", "https"):
        host, port_text, _transport = parts
    elif len(parts) == 2:
        host, port_text = parts
        transport = "tcp"
    else:
        raise ValueError("Endpoint must include host and port")
    return {"name": name, "host": host, "port": int(port_text), "transport": transport}


def sev_to_level(sev):
    """WAF severity string -> GELF/syslog level for Graylog routing."""
    s = (sev or "").upper()
    return {"CRITICAL": 2, "ERROR": 3, "HIGH": 3, "WARNING": 4, "MEDIUM": 4,
            "NOTICE": 5, "INFO": 6}.get(s, 6)


def to_gelf(ev, source_host):
    """Normalized WAF event -> GELF 1.1 message. Custom fields underscore-prefixed."""
    short = (f"WAF {ev.get('waf_action','?')} {ev.get('waf_rule_id','?')} "
             f"{ev.get('waf_method','')} {ev.get('waf_host','?')} from "
             f"{ev.get('waf_client_ip','?')} [{ev.get('waf_severity','?')}]")
    epoch = time.time()
    ts = ev.get("timestamp") or ""
    if ts:
        try:
            epoch = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            pass
    g = {
        "version": "1.1",
        "host": source_host,
        "short_message": short[:250],
        "timestamp": round(epoch, 3),
        "level": sev_to_level(ev.get("waf_severity")),
        "_event_type": ev.get("event_type", "waf_event"),
        "_source": ev.get("source", "socfortress-waf"),
        "_waf_txid": ev.get("waf_txid", ""),
        "_waf_site_id": ev.get("waf_site_id", ""),
        "_waf_client_ip": ev.get("waf_client_ip", ""),
        "_waf_method": ev.get("waf_method", ""),
        "_waf_uri": ev.get("waf_uri", ""),
        "_waf_host": ev.get("waf_host", ""),
        "_waf_rule_id": ev.get("waf_rule_id", ""),
        "_waf_action": ev.get("waf_action", ""),
        "_waf_severity": ev.get("waf_severity", ""),
        "_waf_anomaly_score": ev.get("waf_anomaly_score", 0),
        "_waf_matched_rules": ev.get("waf_matched_rules", ""),
        "_waf_matched_ids": ev.get("waf_matched_ids", ""),
        "_waf_geo_cc": ev.get("waf_geo_cc", ""),
        "_waf_geo_country": ev.get("waf_geo_country", ""),
        "_waf_geo_city": ev.get("waf_geo_city", ""),
        "_waf_raw": ev.get("waf_raw", ""),
        "_event_hash": ev.get("waf_event_id", ""),
    }
    return g


def send_graylog_tcp(events, host, port, source_host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    # SO_LINGER: block on close() until buffered data is flushed (prevents the
    # "socket closed before batch drained" loss seen when many small GELF frames
    # are sent then close() races the flush).
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 10))
    s.connect((host, port))
    n = 0
    for ev in events:
        s.sendall(json.dumps(to_gelf(ev, source_host)).encode() + b"\x00")  # GELF TCP null-delimited
        n += 1
    try:
        s.shutdown(socket.SHUT_WR)   # signal EOF, let the server read the last frame
        s.recv(1)                    # wait for peer to close (drains our send buffer)
    except OSError:
        pass
    s.close()
    return n


def send_graylog_http(events, host, port, source_host, ssl_context):
    connection = http.client.HTTPSConnection(
        host, port, context=ssl_context, timeout=30
    )
    delivered = 0
    try:
        for event in events:
            connection.request(
                "POST",
                "/gelf",
                json.dumps(to_gelf(event, source_host), ensure_ascii=False).encode(),
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"Graylog HTTP delivery returned {response.status}"
                )
            delivered += 1
    finally:
        connection.close()
    return delivered


def wazuh_event(event):
    return {key: value for key, value in event.items() if key != "waf_raw"}


def send_wazuh_tcp(events, host, port):
    connection = socket.create_connection((host, port), timeout=30)
    delivered = 0
    try:
        for event in events:
            connection.sendall(
                json.dumps(wazuh_event(event), ensure_ascii=False).encode() + b"\n"
            )
            delivered += 1
    finally:
        connection.close()
    return delivered


def append_wazuh(events, env, wazuh_path):
    key = os.path.expanduser(env["WAZUH_SSH_KEY"])
    if not os.path.exists(key):
        key = os.path.expanduser("~/.ssh/wazuh_hermes")
    # detection subset for Wazuh: drop the bulky raw blob (Graylog keeps full fidelity)
    lean = []
    for ev in events:
        lean.append(wazuh_event(ev))
    data = "".join(json.dumps(ev, ensure_ascii=False) + "\n" for ev in lean)
    # ensure the target dir exists on the manager, then append
    remote = f"mkdir -p $(dirname {wazuh_path}) && cat >> {wazuh_path}"
    r = subprocess.run(["ssh", "-i", key, "-o", "StrictHostKeyChecking=accept-new",
                        "-o", "BatchMode=yes", f"{env['WAZUH_SSH_USER']}@{env['WAZUH_SSH_HOST']}",
                        remote], input=data, capture_output=True, text=True)
    return r.returncode, r.stderr[:200]


def deliver_then_commit(candidate_state, state_path, events, deliveries):
    results = {name: delivery(events) for name, delivery in deliveries}
    target = Path(state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    shutil.copyfile(candidate_state, temporary)
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=os.path.join(HERE, ".waf_state.json"))
    ap.add_argument("--graylog-port", type=int, default=12203)
    ap.add_argument("--graylog-endpoint", action="append", default=[])
    ap.add_argument("--graylog-ca")
    ap.add_argument("--no-default-graylog", action="store_true")
    ap.add_argument("--wazuh-path", default="/var/ossec/logs/waf/events.jsonl")
    ap.add_argument("--wazuh-endpoint", action="append", default=[])
    ap.add_argument("--no-default-wazuh", action="store_true")
    ap.add_argument("--source-host", default="socfortress-waf")
    ap.add_argument("--page-size", type=int, default=100)
    ap.add_argument("--max-pages", type=int, default=50)
    ap.add_argument("--first-run-limit", type=int, default=0,
                    help="on first run, how many historical events to seed (0 = none; start fresh)")
    ap.add_argument("--no-graylog", action="store_true")
    ap.add_argument("--no-wazuh", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    env = load_env()
    workdir = tempfile.mkdtemp(prefix="wafpipe_")
    state_path = Path(args.state)
    candidate_state = Path(workdir) / "waf-state.candidate.json"
    if state_path.exists():
        shutil.copy2(state_path, candidate_state)

    cmd = [sys.executable, os.path.join(HERE, "waf_collector.py"),
           "--out", workdir, "--state", str(candidate_state),
           "--page-size", str(args.page_size), "--max-pages", str(args.max_pages),
           "--first-run-limit", str(args.first_run_limit)]
    if args.dry_run:
        cmd.append("--dry-run")
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        print("collector failed:", r.stderr[:300]); sys.exit(1)
    if args.dry_run:
        print("dry-run: no delivery"); return

    jl = sorted(f for f in os.listdir(workdir) if f.endswith(".jsonl"))
    if not jl:
        print("no events file produced (no new events)"); return
    events = [json.loads(l) for l in open(os.path.join(workdir, jl[-1])) if l.strip()]
    if not events:
        print("no new WAF events to deliver"); return

    deliveries = []
    if not args.no_graylog:
        endpoints = [parse_endpoint(value) for value in args.graylog_endpoint]
        if not args.no_default_graylog:
            endpoints.insert(
                0,
                {
                    "name": "production-graylog",
                    "host": env["GRAYLOG_HOST"],
                    "port": args.graylog_port,
                    "transport": "tcp",
                },
            )
        tls_context = None
        if any(endpoint["transport"] == "https" for endpoint in endpoints):
            if not args.graylog_ca:
                raise SystemExit("--graylog-ca is required for HTTPS Graylog")
            tls_context = ssl.create_default_context(cafile=args.graylog_ca)
        for endpoint in endpoints:
            def deliver_graylog(batch, endpoint=endpoint):
                if endpoint["transport"] == "https":
                    return send_graylog_http(
                        batch,
                        endpoint["host"],
                        endpoint["port"],
                        args.source_host,
                        tls_context,
                    )
                return send_graylog_tcp(
                    batch, endpoint["host"], endpoint["port"], args.source_host
                )
            deliveries.append((endpoint["name"], deliver_graylog))
    if not args.no_wazuh:
        if not args.no_default_wazuh:
            def deliver_production_wazuh(batch):
                rc, error = append_wazuh(batch, env, args.wazuh_path)
                if rc:
                    raise RuntimeError("Wazuh delivery failed: " + error)
                return len(batch)
            deliveries.append(("production-wazuh", deliver_production_wazuh))
        for value in args.wazuh_endpoint:
            endpoint = parse_endpoint(value)
            if endpoint["transport"] != "tcp":
                raise SystemExit("Wazuh endpoint transport must be tcp")
            deliveries.append(
                (
                    endpoint["name"],
                    lambda batch, endpoint=endpoint: send_wazuh_tcp(
                        batch, endpoint["host"], endpoint["port"]
                    ),
                )
            )

    delivered = deliver_then_commit(
        candidate_state, state_path, events, deliveries
    )
    print(f"delivered {len(events)} WAF events:", json.dumps(delivered))


if __name__ == "__main__":
    main()
