"""Regression checks for evidence classification and credential-safe failures."""

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("covee_lab", ROOT / "scripts/lab.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
PROBE_SPEC = importlib.util.spec_from_file_location("covee_probe", ROOT / "lab/probe.py")
probe = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(probe)


class LabSafetyTests(unittest.TestCase):
    def tearDown(self):
        lab.SECRETS.clear()

    def test_redacts_both_known_and_unseen_key_formats(self):
        lab.SECRETS.add("opaque-preauth-secret")
        result = lab.redact("--auth-key=opaque-preauth-secret hskey-auth-abcd_xyz-123 tskey-auth-987")
        self.assertNotIn("opaque-preauth-secret", result)
        self.assertNotIn("hskey", result)
        self.assertNotIn("tskey", result)

    def test_command_failure_redacts_arguments_stdout_and_stderr(self):
        secret = "hskey-auth-testing-secret"
        completed = subprocess.CompletedProcess([], 1, stdout=secret, stderr="bad " + secret)
        with patch.object(lab.subprocess, "run", return_value=completed):
            with self.assertRaises(lab.LabError) as raised:
                lab.run(["tailscale", "up", "--auth-key=" + secret])
        self.assertNotIn(secret, str(raised.exception))

    def test_invalid_json_does_not_echo_secret_output(self):
        with self.assertRaises(lab.LabError) as raised:
            lab.parse_json("not JSON containing an unknown credential", "test CLI")
        self.assertEqual(str(raised.exception), "Invalid JSON from test CLI")

    def test_proxy_or_payload_failure_cannot_pass_as_policy_denial(self):
        for output in ('{"status":"blocked","phase":"proxy-connect"}',
                       '{"status":"error","phase":"overlay-connect"}',
                       '{"status":"blocked","phase":"http-payload"}'):
            with self.subTest(output=output), self.assertRaises(lab.LabError):
                lab.parse_probe(subprocess.CompletedProcess([], 2, stdout=output, stderr=""))

    def test_only_explicit_socks_dial_failure_is_expected(self):
        output = '{"status":"blocked","phase":"overlay-connect","failure_kind":"socks-connect-rejected","socks_reply":1}'
        result = lab.parse_probe(subprocess.CompletedProcess([], 2, stdout=output, stderr=""))
        self.assertEqual(result["status"], "blocked")
        for value in ({"error": "timeout", "failure_kind": "overlay-connect-timeout"},
                      {"socks_reply": 7, "failure_kind": "socks-connect-rejected"},
                      {"socks_reply": True, "failure_kind": "socks-connect-rejected"},
                      {"socks_reply": 1}):
            value.update({"status": "blocked", "phase": "overlay-connect"})
            with self.subTest(value=value), self.assertRaises(lab.LabError):
                lab.parse_probe(subprocess.CompletedProcess([], 2, stdout=json.dumps(value), stderr=""))

    def test_deleted_self_without_identity_requires_explicit_needs_login_state(self):
        with patch.object(lab, "daemon_status", return_value={"BackendState": "NeedsLogin", "Self": None}):
            self.assertEqual(lab.needs_login("node8"), {"backend_state": "NeedsLogin", "self_id_present": False})
        with patch.object(lab, "daemon_status", return_value={"BackendState": "Running", "Self": None}):
            self.assertFalse(lab.needs_login("node8"))

    def test_bad_client_status_cannot_count_as_peer_withdrawal(self):
        for output in ("not JSON", "null", '{}', '{"BackendState":"NeedsLogin","Self":null}',
                       '{"BackendState":"Running","Self":null}'):
            with self.subTest(output=output), patch.object(lab, "execute", return_value=subprocess.CompletedProcess(
                    [], 0, stdout=output)), self.assertRaises(lab.LabError):
                lab.peer_present("100.64.0.8", service="node2")

    def test_relay_or_tsmp_pong_is_not_direct_udp_evidence(self):
        for via in ("DERP(lab)", "TSMP", "172.19.0.4", "peer-relay(node4)"):
            self.assertFalse(lab.has_direct_pong(f"pong from node (100.64.0.2) via {via} in 1ms"))
        self.assertTrue(lab.has_direct_pong("pong from node (100.64.0.2) via 172.19.0.4:35851 in 1ms"))
        self.assertTrue(lab.has_direct_pong("pong from node (100.64.0.2) via [fd00::4]:35851 in 1ms"))

    def test_tsmp_failure_preserves_prior_direct_ping_evidence(self):
        nodes = [{"given_name": "lab-node2", "ip_addresses": ["100.64.0.2"]}]

        def execution(_service, _program, *arguments, **_kwargs):
            if "--tsmp" in arguments:
                raise lab.LabError("TSMP failed")
            output = "pong from lab-node2 via 172.19.0.9:1234 in 1ms" if "ping" in arguments else "version"
            return subprocess.CompletedProcess([], 0, stdout=output, stderr="")

        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "results.json"
            with patch.object(lab, "RESULT", result_path), patch.object(lab, "up", return_value=nodes), \
                 patch.object(lab, "control", return_value=subprocess.CompletedProcess([], 0, stdout="version")), \
                 patch.object(lab, "compose", return_value=subprocess.CompletedProcess([], 0, stdout="[]")), \
                 patch.object(lab, "execute", side_effect=execution), patch.object(lab, "log"):
                with self.assertRaises(lab.LabError):
                    lab.check()
            result = json.loads(result_path.read_text())
        self.assertEqual(result["status"], "failed")
        self.assertIn("pong from", result["checks"]["direct"])
        self.assertNotIn("tsmp", result["checks"])


class ProbeHTTPTests(unittest.TestCase):
    class Connection:
        def __init__(self, response):
            self.incoming = b"\x05\x00\x05\x00\x00\x01" + b"\x00" * 6 + response
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def recv(self, length):
            result, self.incoming = self.incoming[:length], self.incoming[length:]
            return result

        def sendall(self, value):
            self.sent.append(value)

    def test_overlay_ip_and_http_peer_hostname_are_distinct(self):
        connection = self.Connection(b"HTTP/1.0 200 OK\r\n\r\n" + probe.PAYLOAD)
        output = io.StringIO()
        with patch.object(probe.socket, "create_connection", return_value=connection), contextlib.redirect_stdout(output):
            code = probe.fetch("node1", "100.64.0.2", 8080, "lab-node2.lab.tail")
        self.assertEqual(code, 0)
        self.assertIn(b"Host: lab-node2.lab.tail:8080\r\n", connection.sent[-1])
        self.assertEqual(connection.sent[1][4:8], bytes([100, 64, 0, 2]))
        self.assertEqual(json.loads(output.getvalue())["status"], "ok")

    def test_non_200_fails_with_status_line_without_echoing_response_body(self):
        connection = self.Connection(b"HTTP/1.0 404 Not Found\r\n\r\nprivate-response-body")
        output = io.StringIO()
        with patch.object(probe.socket, "create_connection", return_value=connection), contextlib.redirect_stdout(output):
            code = probe.fetch("node1", "100.64.0.2", 8080, "lab-node2.lab.tail")
        self.assertEqual(code, 1)
        self.assertIn("HTTP/1.0 404 Not Found", output.getvalue())
        self.assertNotIn("private-response-body", output.getvalue())

    def test_incomplete_or_invalid_socks_failure_reply_is_not_denial(self):
        for reply in (b"\x05\x01\x00\x01", b"\x05\x01\x01\x01" + b"\x00" * 6,
                      b"\x05\x07\x00\x01" + b"\x00" * 6):
            connection = self.Connection(b"")
            connection.incoming = b"\x05\x00" + reply
            output = io.StringIO()
            with self.subTest(reply=reply), patch.object(probe.socket, "create_connection", return_value=connection), \
                 contextlib.redirect_stdout(output):
                code = probe.fetch("node8", "100.64.0.2", 8080, "lab-node2.lab.tail")
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["status"], "error")

    def test_complete_socks_failure_reply_records_fresh_dial_evidence(self):
        connection = self.Connection(b"")
        connection.incoming = b"\x05\x00\x05\x01\x00\x01" + b"\x00" * 6
        output = io.StringIO()
        with patch.object(probe.socket, "create_connection", return_value=connection), contextlib.redirect_stdout(output):
            code = probe.fetch("node8", "100.64.0.2", 8080, "lab-node2.lab.tail")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["proxy"], "node8")
        self.assertEqual(json.loads(output.getvalue())["socks_reply"], 1)


class RevocationEvidenceTests(unittest.TestCase):
    nodes = [{"given_name": "lab-node8", "id": "8", "ip_addresses": ["100.64.0.8"]}]
    payload = {"status": "ok", "payload": "covee-overlay-proof-v1"}

    @staticmethod
    def immediately(description, operation, **_kwargs):
        result = operation()
        if not result:
            raise lab.LabError(f"Waiting for {description}")
        return result

    def test_failed_positive_probe_prevents_deletion(self):
        report = {"checks": {}}
        with patch.object(lab, "wait_for", side_effect=self.immediately), patch.object(lab, "write_result"), \
             patch.object(lab, "log"), patch.object(lab, "expect_payload", return_value=False), \
             patch.object(lab, "headscale") as control:
            with self.assertRaises(lab.LabError):
                lab.check_revocation(self.nodes, "100.64.0.2", "lab-node2.lab.tail", report)
        control.assert_not_called()
        self.assertNotIn("fresh_connection_denied", report["checks"]["revocation"])

    def test_backend_probe_error_preserves_positive_evidence_without_passing_revocation(self):
        report = {"checks": {}}
        with patch.object(lab, "wait_for", side_effect=self.immediately), patch.object(lab, "write_result"), \
             patch.object(lab, "log"), patch.object(lab, "expect_payload", return_value=self.payload), \
             patch.object(lab, "headscale", return_value=[]), \
             patch.object(lab, "peer_present", side_effect=[True, True, False, False]), \
             patch.object(lab, "needs_login", return_value={"backend_state": "NeedsLogin", "self_id_present": False}), \
             patch.object(lab, "fetch", side_effect=lab.LabError("HTTP backend failed")):
            with self.assertRaisesRegex(lab.LabError, "HTTP backend failed"):
                lab.check_revocation(self.nodes, "100.64.0.2", "lab-node2.lab.tail", report)
        evidence = report["checks"]["revocation"]
        self.assertEqual(evidence["before_delete_payload"], self.payload)
        self.assertEqual(evidence["peer_maps_removed"], ["node1", "node2"])
        self.assertNotIn("fresh_connection_denied", evidence)

    def test_failed_surviving_peer_probe_cannot_pass_revocation(self):
        report = {"checks": {}}
        with patch.object(lab, "wait_for", side_effect=self.immediately), patch.object(lab, "write_result"), \
             patch.object(lab, "log"), patch.object(lab, "expect_payload", side_effect=[self.payload, False]), \
             patch.object(lab, "headscale", return_value=[]), \
             patch.object(lab, "peer_present", side_effect=[True, True, False, False]), \
             patch.object(lab, "needs_login", return_value={"backend_state": "NeedsLogin", "self_id_present": False}), \
             patch.object(lab, "fetch", return_value={"status": "blocked", "socks_reply": 1}):
            with self.assertRaises(lab.LabError):
                lab.check_revocation(self.nodes, "100.64.0.2", "lab-node2.lab.tail", report)
        self.assertNotIn("fresh_connection_denied", report["checks"]["revocation"])
        self.assertEqual(report["checks"]["revocation"]["established_session_behavior"], "not_tested")


if __name__ == "__main__":
    unittest.main()
