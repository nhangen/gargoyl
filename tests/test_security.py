import unittest
from unittest.mock import patch
from gargoyl.security import CollectionIdentity, SpoolCipher, RetentionPolicy, export_batch, TransportConfig, prepare_transmission
from gargoyl.telemetry import PolicyError
from test_telemetry import snapshot

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.identity = CollectionIdentity(snapshot()["host_id"])
        self.cipher = SpoolCipher(self.identity, b'x' * 32)

    def test_authenticated_encryption(self):
        data = snapshot(); encrypted = self.cipher.seal(data)
        self.assertNotIn(b'running', encrypted)
        self.assertEqual(self.cipher.open(encrypted), data)
        self.assertNotEqual(encrypted, self.cipher.seal(data))
        for altered in (encrypted[:-1], encrypted[:-1] + bytes([encrypted[-1] ^ 1])):
            with self.assertRaises(PolicyError): self.cipher.open(altered)
        with self.assertRaises(PolicyError): SpoolCipher(self.identity, b'y' * 32).open(encrypted)
        other = CollectionIdentity('00000000-0000-4000-8000-000000000002')
        with self.assertRaises(PolicyError): SpoolCipher(other, b'x' * 32).open(encrypted)

    def test_reject_before_storage_and_transport(self):
        data = snapshot(); data['raw_logs'] = 'synthetic-marker'
        for call in (self.cipher.seal, lambda value: prepare_transmission(value, self.identity)):
            with self.assertRaises(PolicyError): call(data)
        data = snapshot(); data['host_id'] = '00000000-0000-4000-8000-000000000002'
        for call in (self.cipher.seal, lambda value: prepare_transmission(value, self.identity)):
            with self.assertRaises(PermissionError): call(data)

    def test_collection_has_no_repair_authority(self):
        self.identity.authorize('telemetry:write', self.identity.host_id)
        for action in ('repair', 'restart', 'model:download', 'credentials:rotate'):
            with self.assertRaises(PermissionError): self.identity.authorize(action, self.identity.host_id)
        self.assertFalse(hasattr(self.identity, 'repair'))

    def test_retention_and_export(self):
        self.assertEqual(export_batch([snapshot()], '2026-01-03T00:00:00Z'), [])
        self.assertEqual(export_batch([snapshot()], '2025-12-31T00:00:00Z'), [])
        self.assertEqual(len(export_batch([snapshot()] * 3, '2026-01-01T00:00:01Z', RetentionPolicy(max_records=2))), 2)
        data = snapshot(); data['credential'] = 'synthetic-marker'
        with self.assertRaises(PolicyError): export_batch([data], '2026-01-03T00:00:00Z')

    def test_transport_fails_closed(self):
        for endpoint in ('http://collector.example.test', 'https://user:pass@collector.example.test', 'https://collector.example.test/?secret=x'):
            with self.assertRaises(ValueError): TransportConfig(endpoint, 'ca', 'cert', 'key')
        config = TransportConfig('https://collector.example.test/ingest', 'ca', 'cert', 'key')
        with patch('gargoyl.security.ssl.create_default_context') as create:
            context = config.ssl_context()
            create.assert_called_once_with(cafile='ca')
            context.load_cert_chain.assert_called_once_with('cert', 'key')
        with self.assertRaises(OSError): config.ssl_context()
