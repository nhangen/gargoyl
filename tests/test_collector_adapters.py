import unittest

from gargoyl.collector_adapters import execution_failure, parse_observations
from gargoyl.telemetry import PolicyError

NOW = "2026-01-01T00:00:00Z"
STATUS = "darkbloom_status_text_v1"
DOCTOR = "darkbloom_doctor_text_v1"
# Synthetic values, exact punctuation verified against pinned producer source.
DOCTOR_TEXT = """Darkbloom Doctor — System Diagnostics

1. Hardware detection........... ✓ Synthetic Chip (64 GB, 32 GPU cores)
2. System Integrity Protection.. ✓ Enabled
3. Secure Enclave.............. ✓ Available
4. MDM enrollment.............. ✓ Enrolled
5. Inference runtime........... ✓ vllm-mlx 0.0.1
6. Downloaded models........... ✓ 2 model(s) found
7. Text E2E key................ ✓ Secure Enclave-backed
8. Coordinator connectivity.... ✓ Online (3 providers)

Result: 8/8 checks passed

All good! Start serving with: darkbloom serve
"""


def parse(kind, text):
    return parse_observations(kind, text.encode(), observed_at=NOW)


class AdapterTests(unittest.TestCase):
    def test_status_states_and_no_residency_inference(self):
        for text, value in (("● Running", "running"), ("○ Stopped", "stopped"),
                            ("● Running — serving synthetic-private-model", "running")):
            result = parse(STATUS, f"  Darkbloom Provider Status\n  Status:     {text}\n")
            self.assertEqual(result.errors, ())
            self.assertEqual(set(result.readings), {"daemon_state"})
            self.assertEqual(result.readings["daemon_state"]["value"], value)
            self.assertNotIn("synthetic-private", repr(result))

    def test_status_ambiguity_rejected(self):
        for text in ("", "Status: ● Running\nStatus: ○ Stopped", "Status: ● Running\nStatus: ● Running",
                     "Status: ● Running extra", "Status: ○ Stopped — serving synthetic",
                     "Status: ● Running — serving "):
            self.assertEqual(parse(STATUS, text).errors, ("invalid_state",))

    def test_doctor_complete_and_failed_with_numbered_advice(self):
        self.assertEqual(parse(DOCTOR, DOCTOR_TEXT).readings["doctor_state"]["value"], "passed")
        failed = DOCTOR_TEXT.replace("✓ Enabled", "✗ DISABLED — provider cannot serve safely").replace(
            "Result: 8/8", "Result: 7/8").replace("All good! Start serving with: darkbloom serve",
            "Issues to fix:\n  1. Synthetic repair advice\n     1. More synthetic advice")
        result = parse(DOCTOR, failed)
        self.assertEqual(result.readings["doctor_state"]["value"], "failed")
        self.assertNotIn("advice", repr(result))

    def test_doctor_nonmac_skips_match_producer_count(self):
        text = DOCTOR_TEXT.replace("✓ Available", "- Not applicable (non-macOS)").replace(
            "✓ Enrolled", "- Not applicable (non-macOS)")
        self.assertEqual(parse(DOCTOR, text).readings["doctor_state"]["value"], "passed")

    def test_doctor_missing_duplicate_contradictory_malformed(self):
        lines = DOCTOR_TEXT.splitlines()
        cases = [DOCTOR_TEXT.replace("Result: 8/8", "Result: 7/8"),
                 DOCTOR_TEXT.replace("✓ Enabled", "✗ DISABLED — provider cannot serve safely"),
                 DOCTOR_TEXT.replace("✓ Enabled", "✓ DISABLED"),
                 DOCTOR_TEXT.replace("✓ 2 model(s)", "✓ 0 model(s)"),
                 DOCTOR_TEXT.replace("✓ Enabled", "✓ Enabled ✗ DISABLED"),
                 DOCTOR_TEXT + "Result: 8/8 checks passed\n",
                 DOCTOR_TEXT + "2. System Integrity Protection.. ✓ Enabled\n",
                 DOCTOR_TEXT.replace("2. System Integrity Protection..", "2. SIP.."),
                 DOCTOR_TEXT.replace("Result: 8/8", "Result: 8/9")]
        for n in range(2, 10):
            cases.append("\n".join(lines[:n] + lines[n+1:]))
            cases.append("\n".join(lines[:n] + [lines[n]] + lines[n:]))
        for text in cases:
            with self.subTest(text=text[:50]):
                result = parse(DOCTOR, text)
                self.assertEqual(result.readings, {})
                self.assertEqual(result.errors, ("invalid_state",))

    def test_size_utf8_controls_and_safe_errors(self):
        good = b"Status: " + "● Running".encode() + b"\n"
        self.assertFalse(parse_observations(STATUS, good + b"x" * (65536-len(good)), observed_at=NOW).errors)
        for payload in (good + b"x" * 65536, b"\xff", good+b"\x1b", good+b"\0", good+b"\r", "Status: ● Running\u2028".encode()):
            result = parse_observations(STATUS, payload, observed_at=NOW)
            self.assertEqual(result.errors, ("invalid_state",))
            self.assertEqual(result.readings, {})
        self.assertFalse(parse(STATUS, "Status: ● Running\r\n").errors)

    def test_configuration_failures_and_metadata(self):
        for kwargs in ({"source_kind": "unknown", "observed_at": NOW},
                       {"source_kind": STATUS, "observed_at": "synthetic-secret"},
                       {"source_kind": STATUS, "observed_at": NOW, "ttl": True}):
            with self.assertRaises(PolicyError) as error:
                parse_observations(payload=b"", **kwargs)
            self.assertNotIn("synthetic-secret", str(error.exception))
        field = parse(STATUS, "Status: ● Running").readings["daemon_state"]
        self.assertEqual((field["source"], field["timestamp"], field["freshness_seconds"]), ("daemon", NOW, 60))
        for code in ("timeout", "permission_denied", "unavailable"):
            self.assertEqual(execution_failure(code).errors, (code,))
        with self.assertRaises(PolicyError):
            execution_failure("synthetic-secret")
