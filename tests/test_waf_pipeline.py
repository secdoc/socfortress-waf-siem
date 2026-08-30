#!/usr/bin/env python3
import importlib.util
import errno
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Response:
    def __init__(self, status):
        self.status = status

    def read(self):
        return b""


class FakeHttp:
    statuses = []
    requests = []

    def __init__(self, host, port, context=None, timeout=None):
        self.host = host
        self.port = port
        self.context = context

    def request(self, method, path, body, headers):
        self.requests.append((method, path, json.loads(body), headers))

    def getresponse(self):
        return Response(self.statuses.pop(0))

    def close(self):
        pass


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendall(self, value):
        self.sent.append(value)

    def close(self):
        pass


class WafPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.collector = load("waf_collector_test", ROOT / "collector/waf_collector.py")
        cls.pipeline = load("waf_pipeline_test", ROOT / "collector/waf_pipeline.py")

    def sample(self):
        return {
            "id": "event-1",
            "timestamp": "2026-08-30T18:00:00Z",
            "transaction_id": "tx-1",
            "site_id": "site-1",
            "client_ip": "198.51.100.10",
            "method": "GET",
            "uri": "/login",
            "host": "example.test",
            "rule_id": "930130",
            "action": "blocked",
            "severity": "CRITICAL",
            "matched_rules": [{"id": "930130", "msg": "Restricted File Access"}],
            "raw_log": {},
        }

    def test_normalized_event_has_stable_complete_identity(self):
        first = self.collector.normalize(self.sample())
        reordered = self.collector.normalize(dict(reversed(list(self.sample().items()))))
        changed = self.sample()
        changed["transaction_id"] = "tx-2"
        second = self.collector.normalize(changed)

        self.assertEqual(len(first["waf_event_id"]), 64)
        self.assertEqual(first["waf_event_id"], reordered["waf_event_id"])
        self.assertNotEqual(first["waf_event_id"], second["waf_event_id"])
        self.assertEqual(
            self.pipeline.to_gelf(first, "socfortress-waf")["_event_hash"],
            first["waf_event_id"],
        )

    def test_endpoint_parser_supports_acknowledged_https(self):
        endpoint = self.pipeline.parse_endpoint(
            "target=graylog.example.local:12215:https"
        )
        self.assertEqual(
            endpoint,
            {
                "name": "target",
                "host": "graylog.example.local",
                "port": 12215,
                "transport": "https",
            },
        )

    def test_http_graylog_requires_success_per_event(self):
        FakeHttp.requests = []
        FakeHttp.statuses = [202, 503]
        events = [self.collector.normalize(self.sample()), self.collector.normalize(self.sample())]
        with mock.patch.object(self.pipeline.http.client, "HTTPSConnection", FakeHttp):
            with self.assertRaisesRegex(RuntimeError, "503"):
                self.pipeline.send_graylog_http(events, "graylog.example", 12215, "waf", object())
        self.assertEqual(len(FakeHttp.requests), 2)
        self.assertTrue(all(request[1] == "/gelf" for request in FakeHttp.requests))

    def test_wazuh_tcp_is_newline_delimited(self):
        fake = FakeSocket()
        event = self.collector.normalize(self.sample())
        with mock.patch.object(self.pipeline.socket, "create_connection", return_value=fake):
            delivered = self.pipeline.send_wazuh_tcp([event], "wazuh.example", 5514)
        self.assertEqual(delivered, 1)
        self.assertEqual(len(fake.sent), 1)
        self.assertTrue(fake.sent[0].endswith(b"\n"))
        expected = {key: value for key, value in event.items() if key != "waf_raw"}
        self.assertEqual(json.loads(fake.sent[0]), expected)

    def test_delivery_failure_does_not_commit_candidate_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            candidate = root / "candidate.json"
            state.write_text('{"high_water":"old"}\n')
            candidate.write_text('{"high_water":"new"}\n')

            def fail(_events):
                raise RuntimeError("consumer failed")

            with self.assertRaisesRegex(RuntimeError, "consumer failed"):
                self.pipeline.deliver_then_commit(
                    candidate,
                    state,
                    [{}],
                    [("graylog", lambda _events: 1), ("wazuh", fail)],
                )
            self.assertEqual(json.loads(state.read_text())["high_water"], "old")

    def test_all_consumers_succeed_before_atomic_state_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            candidate = root / "candidate.json"
            state.write_text('{"high_water":"old"}\n')
            candidate.write_text('{"high_water":"new"}\n')
            results = self.pipeline.deliver_then_commit(
                candidate,
                state,
                [{}],
                [("graylog", lambda _events: 1), ("wazuh", lambda _events: 1)],
            )
            self.assertEqual(results, {"graylog": 1, "wazuh": 1})
            self.assertEqual(json.loads(state.read_text())["high_water"], "new")

    def test_state_commit_is_atomic_across_filesystems(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            state = Path(first) / "state.json"
            candidate = Path(second) / "candidate.json"
            state.write_text('{"high_water":"old"}\n')
            candidate.write_text('{"high_water":"new"}\n')
            real_replace = self.pipeline.os.replace

            def replace(source, target):
                if Path(source).parent != Path(target).parent:
                    raise OSError(errno.EXDEV, "cross-device link")
                return real_replace(source, target)

            with mock.patch.object(self.pipeline.os, "replace", side_effect=replace):
                self.pipeline.deliver_then_commit(
                    candidate,
                    state,
                    [{}],
                    [("graylog", lambda _events: 1), ("wazuh", lambda _events: 1)],
                )
            self.assertEqual(json.loads(state.read_text())["high_water"], "new")

if __name__ == "__main__":
    unittest.main()
