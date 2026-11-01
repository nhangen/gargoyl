"""Synthetic mTLS ingestion, durable store and loopback viewer integration."""
import hashlib
import http.client
import os
import sqlite3
import ssl
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path

from ingestion_test_support import test_pki
from test_dashboard import HOST, NOW, snapshot

from gargoyl.dashboard.runtime import EvidenceViewer
from gargoyl.ingestion import EvidenceStore, IngestionService, Principal
from gargoyl.ingestion_http import make_ingestion_server
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import encode_snapshot


class DashboardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pki = test_pki(self.root)
        self.ciphers = {HOST: SpoolCipher(CollectionIdentity(HOST), os.urandom(32))}
        self.clock = NOW
        self.store = self.open_store()
        self.listeners = []
        self.addCleanup(self.close_runtime)
        self.start_runtime()

    def open_store(self):
        return EvidenceStore(self.root / 'receiver', self.ciphers,
                             RetentionPolicy(max_records=20), self.clock)

    def start(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        self.listeners.append((server, thread))
        return server

    def start_runtime(self):
        grants = frozenset({('daemon_state', 'daemon'), ('daemon_state', 'coordinator')})
        principal = Principal(frozenset({HOST}), grants)
        service = IngestionService(self.store, {hashlib.sha256(self.pki['client'][2]).hexdigest(): principal})
        self.receiver = self.start(make_ingestion_server(
            service, ca_file=self.pki['ca'], certificate_file=self.pki['server'][0],
            private_key_file=self.pki['server'][1], clock=lambda: self.clock))
        self.absent = '00000000-0000-4000-8000-000000000002'
        self.viewer = self.start(EvidenceViewer(self.store, [HOST, self.absent], clock=lambda: self.clock))

    def stop_listeners(self):
        for server, thread in self.listeners:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()
            self.assertFalse(thread.is_alive())
        self.listeners.clear()

    def close_runtime(self):
        self.stop_listeners()
        self.store.close()

    def ingest(self, data):
        context = ssl.create_default_context(cafile=self.pki['ca'])
        context.load_cert_chain(*self.pki['client'][:2])
        connection = http.client.HTTPSConnection('localhost', self.receiver.server_port, context=context, timeout=3)
        try:
            connection.request('POST', '/v1/snapshots', body=encode_snapshot(data),
                               headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def page(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.viewer.server_port, timeout=3)
        try:
            connection.request('GET', '/')
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def test_tls_ingestion_restart_readback_conflict_and_staleness(self):
        self.assertIn('No report', self.page()[1])
        self.assertEqual(self.ingest(snapshot()), 204)
        self.assertEqual(self.ingest(snapshot(value='stopped', source='coordinator')), 204)
        # Both acknowledgements precede the read; next viewer request sees durable data.
        status, page = self.page()
        self.assertEqual(status, 200)
        self.assertIn('daemon_state: mismatch', page)
        self.assertIn(self.absent, page)
        self.assertIn('missing_collector_heartbeat', page)
        self.assertIn('content="30"', page)
        self.stop_listeners()
        self.store.close()
        self.store = self.open_store()
        self.start_runtime()
        self.assertIn('daemon_state: mismatch', self.page()[1])
        # Canonical replay dedupes, contradictory evidence does not.
        self.assertEqual(self.ingest(snapshot()), 204)
        self.assertEqual(len(self.store.snapshots(now=self.clock)), 2)
        self.assertEqual(self.ingest(snapshot(value='stopped')), 204)
        status, page = self.page()
        self.assertEqual(status, 200)
        self.assertIn('unknown — conflicting observations', page)
        self.assertIn('<td>running</td>', page)
        self.assertIn('<td>stopped</td>', page)
        self.assertIn('daemon_state: unknown', page)
        self.clock = '2026-01-01T00:05:01Z'
        page = self.page()[1]
        self.assertIn('stale (reported: observed)', page)
        self.assertIn(self.clock, page)
        # Future-relative evidence survives storage but is never current health.
        self.assertEqual(self.ingest(snapshot(at='2026-01-01T00:06:00Z')), 204)
        self.assertIn('unknown (reported: observed)', self.page()[1])

    def test_corrupt_store_returns_unavailable_then_recovers(self):
        self.assertEqual(self.ingest(snapshot()), 204)
        self.assertIn('<td>running</td>', self.page()[1])
        # Inject authenticated-storage damage, not a fake reader exception.
        database = self.root / 'receiver' / 'evidence.sqlite3'
        with closing(sqlite3.connect(database)) as db, db:
            original = db.execute('SELECT payload FROM evidence').fetchone()[0]
            damaged = bytearray(original)
            damaged[-1] ^= 1
            db.execute('UPDATE evidence SET payload = ?', (bytes(damaged),))
        status, page = self.page()
        self.assertEqual(status, 503)
        self.assertIn('Fleet state is unknown', page)
        self.assertNotIn('running', page)
        self.assertNotIn(str(self.root), page)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('UPDATE evidence SET payload = ?', (original,))
        status, page = self.page()
        self.assertEqual(status, 200)
        self.assertIn('<td>running</td>', page)
