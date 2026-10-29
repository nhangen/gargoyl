"""Regression coverage for the wire/storage round-trip size invariant."""

import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_telemetry import snapshot

from gargoyl.security import (
    CollectionIdentity,
    RetentionPolicy,
    SpoolCipher,
    export_batch,
    prepare_transmission,
)
from gargoyl.telemetry import (
    MAX_PAYLOAD_BYTES,
    MAX_TIMESTAMP_CHARACTERS,
    PolicyError,
    decode_snapshot,
    encode_snapshot,
    validate_snapshot,
)


class SizeLimitTests(unittest.TestCase):
    def setUp(self):
        self.identity = CollectionIdentity(snapshot()["host_id"])
        self.key = b"x" * 32
        self.cipher = SpoolCipher(self.identity, self.key)
        self.now = "2026-01-01T00:00:01Z"

    def outbound_operations(self):
        return (
            validate_snapshot,
            encode_snapshot,
            self.cipher.seal,
            lambda data: prepare_transmission(data, self.identity),
            lambda data: RetentionPolicy().select([data], self.now),
            lambda data: export_batch([data], self.now),
        )

    def encrypted_raw(self, payload):
        # Synthetic authenticated inbound bytes, independent of outbound validation.
        nonce = b"n" * 12
        context = ("gargoyl:spool:v1:" + self.identity.host_id).encode()
        return b"GSP1" + nonce + AESGCM(self.key).encrypt(nonce, payload, context)

    def assert_safe_rejection(self, operation, data):
        with self.assertRaises(PolicyError) as caught:
            operation(data)
        self.assertLess(len(str(caught.exception)), 100)
        self.assertNotIn("2026-01-01", str(caught.exception))

    def test_oversized_timestamps_rejected_at_every_boundary(self):
        for location in ("collected_at", "timestamp"):
            for size in (MAX_TIMESTAMP_CHARACTERS + 1, 70021):
                with self.subTest(location=location, size=size):
                    value = "2026-01-01T00:00:00." + "0" * (size - 21) + "Z"
                    self.assertEqual(len(value), size)
                    data = snapshot()
                    if location == "collected_at":
                        data[location] = value
                    else:
                        data["fields"]["daemon_state"][location] = value
                    for operation in self.outbound_operations():
                        self.assert_safe_rejection(operation, data)
                    raw = json.dumps(data).encode()
                    self.assert_safe_rejection(decode_snapshot, raw)
                    self.assert_safe_rejection(
                        self.cipher.open, self.encrypted_raw(raw)
                    )

    def test_supported_timestamp_boundary_roundtrips(self):
        for value in (
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.000000+00:00",
            "2026-01-01T00:00:00.000000Z",
        ):
            data = snapshot()
            data["collected_at"] = value
            data["fields"]["daemon_state"]["timestamp"] = value
            self.assertLessEqual(len(value), MAX_TIMESTAMP_CHARACTERS)
            payload = encode_snapshot(data)
            self.assertEqual(decode_snapshot(payload), data)
            self.assertEqual(self.cipher.open(self.cipher.seal(data)), data)
            self.assertEqual(prepare_transmission(data, self.identity), payload)
            self.assertEqual(RetentionPolicy().select([data], self.now), [data])
            self.assertEqual(export_batch([data], self.now), [payload])

    def test_inbound_plaintext_and_ciphertext_size_boundaries(self):
        payload = encode_snapshot(snapshot())
        for size in (MAX_PAYLOAD_BYTES - 1, MAX_PAYLOAD_BYTES):
            padded = payload + b" " * (size - len(payload))
            self.assertEqual(decode_snapshot(padded), snapshot())
            encrypted = self.encrypted_raw(padded)
            self.assertEqual(len(encrypted), size + 32)
            self.assertEqual(self.cipher.open(encrypted), snapshot())
        oversized = payload + b" " * (MAX_PAYLOAD_BYTES + 1 - len(payload))
        self.assert_safe_rejection(decode_snapshot, oversized)
        self.assert_safe_rejection(self.cipher.open, self.encrypted_raw(oversized))

    def test_serialized_limit_is_enforced_before_all_outbound_operations(self):
        # Valid v1 fields are naturally far below 64KiB after timestamp bounding.
        # Lower the same central limit to exercise the outbound size guard itself.
        data = snapshot()
        size = len(encode_snapshot(data))
        with patch("gargoyl.telemetry.MAX_PAYLOAD_BYTES", size):
            for operation in self.outbound_operations():
                operation(data)
            self.assertEqual(decode_snapshot(encode_snapshot(data)), data)
        with patch("gargoyl.telemetry.MAX_PAYLOAD_BYTES", size - 1):
            for operation in self.outbound_operations():
                self.assert_safe_rejection(operation, data)

    def test_timestamp_grammar_rejects_malformed_inputs_safely(self):
        values = (
            "2026-01-01\ud80000:00:00Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01X00:00:00Z",
            "2026-01-01T00:00:00.0000000Z",
            "2026-01-01T00:00:00,123Z",
            "2026-01-01T00:00:00+01:00",
            "20260101T000000Z",
            "2026-02-30T00:00:00Z",
            "2026-01-01T00:00:00Z\n",
        )
        for location in ("collected_at", "timestamp"):
            for value in values:
                with self.subTest(location=location, value=repr(value)):
                    data = snapshot()
                    if location == "collected_at":
                        data[location] = value
                    else:
                        data["fields"]["daemon_state"][location] = value
                    for operation in self.outbound_operations():
                        self.assert_safe_rejection(operation, data)
                    raw = json.dumps(data).encode()
                    self.assert_safe_rejection(decode_snapshot, raw)
                    self.assert_safe_rejection(
                        self.cipher.open, self.encrypted_raw(raw)
                    )
