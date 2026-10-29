import contextlib
import http.client
import io
import socket
import threading
import time
import unittest
from unittest.mock import patch

from test_dashboard import HOST, NOW, snapshot

from gargoyl.dashboard.runtime import EvidenceViewer


class Reader:
    def __init__(self, records=()):
        self.records = list(records)
        self.calls = []
        self.failure = False

    def snapshots(self, *, now):
        self.calls.append(now)
        if self.failure:
            raise RuntimeError('synthetic-private-storage-path')
        return self.records


class ViewerTests(unittest.TestCase):
    def request(self, viewer, method='GET', path='/', headers=None):
        worker = threading.Thread(target=viewer.handle_request)
        worker.start()
        connection = http.client.HTTPConnection('127.0.0.1', viewer.server_port, timeout=5)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()
            worker.join(timeout=6)
        self.assertFalse(worker.is_alive())
        return result

    def test_request_time_freshness_refresh_and_missing_inventory(self):
        reader = Reader([snapshot(), snapshot(value='stopped', source='coordinator')])
        clock = [NOW]
        absent = '00000000-0000-4000-8000-000000000002'
        with EvidenceViewer(reader, [HOST, absent], clock=lambda: clock[0]) as viewer:
            self.assertEqual(viewer.server_address[0], '127.0.0.1')
            status, headers, page = self.request(viewer)
            self.assertEqual(status, 200)
            self.assertIn('daemon_state: mismatch', page)
            self.assertIn(absent, page)
            self.assertIn('missing_collector_heartbeat', page)
            self.assertIn('http-equiv="refresh" content="30"', page)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
            clock[0] = '2026-01-01T00:05:01Z'
            _, _, page = self.request(viewer)
            self.assertIn('daemon_state: unknown', page)
            self.assertIn('stale (reported: observed)', page)
            self.assertEqual(reader.calls, [NOW, clock[0]])

    def test_new_evidence_visible_on_next_refresh_within_minute(self):
        reader = Reader([snapshot()])
        clock = [NOW]
        with EvidenceViewer(reader, [HOST], clock=lambda: clock[0], refresh_seconds=60) as viewer:
            self.assertNotIn('daemon_state: mismatch', self.request(viewer)[2])
            reader.records.append(snapshot(value='stopped', source='coordinator'))
            clock[0] = '2026-01-01T00:01:00Z'
            page = self.request(viewer)[2]
            self.assertIn('daemon_state: mismatch', page)
            self.assertIn('content="60"', page)

    def test_storage_failure_invalid_evidence_and_recovery(self):
        reader = Reader([snapshot()])
        with EvidenceViewer(reader, [HOST], clock=lambda: NOW) as viewer:
            self.assertEqual(self.request(viewer)[0], 200)
            reader.failure = True
            capture = io.StringIO()
            with contextlib.redirect_stderr(capture):
                status, _, page = self.request(viewer)
            self.assertEqual(status, 503)
            self.assertIn('Fleet state is unknown', page)
            self.assertNotIn('running', page)
            self.assertNotIn('synthetic-private', page + capture.getvalue())
            reader.failure = False
            reader.records[0]['fields']['daemon_state']['value'] = '<script>synthetic</script>'
            status, _, page = self.request(viewer)
            self.assertEqual(status, 503)
            self.assertNotIn('<script>', page)
            reader.records = [snapshot()]
            self.assertEqual(self.request(viewer)[0], 200)

    def test_read_only_host_origin_and_path_guards(self):
        reader = Reader()
        with EvidenceViewer(reader, [HOST], clock=lambda: NOW) as viewer:
            for method, path, headers, status in (
                ('POST', '/', {}, 501), ('GET', '/unknown?private=synthetic', {}, 404),
                ('GET', '/', {'Host': 'evil.invalid'}, 403),
                ('GET', '/', {'Origin': 'https://evil.invalid'}, 403),
            ):
                with self.subTest(method=method, path=path, headers=headers):
                    actual, _, page = self.request(viewer, method, path, headers)
                    self.assertEqual(actual, status)
                    self.assertNotIn('synthetic', page)
            self.assertEqual(reader.calls, [])
            status, headers, page = self.request(viewer, 'HEAD')
            self.assertEqual(status, 200)
            self.assertEqual(page, '')
            self.assertGreater(int(headers['Content-Length']), 0)

    def test_conflicts_and_future_evidence_survive_http_rendering(self):
        conflict = snapshot(value='stopped')
        future = snapshot(source='doctor', at='2026-01-01T00:01:00Z')
        reader = Reader([snapshot(), conflict, future])
        with EvidenceViewer(reader, [HOST], clock=lambda: NOW) as viewer:
            status, _, page = self.request(viewer)
            self.assertEqual(status, 200)
            self.assertIn('unknown — conflicting observations', page)
            self.assertIn('<td>running</td>', page)
            self.assertIn('<td>stopped</td>', page)
            self.assertIn('unknown (reported: observed)', page)
            self.assertIn('daemon_state: unknown', page)

    def test_dripped_headers_hit_absolute_deadline(self):
        reader = Reader()
        with patch('gargoyl.dashboard.runtime.HEADER_DEADLINE_SECONDS', 0.15):
            with EvidenceViewer(reader, [HOST], clock=lambda: NOW) as viewer:
                worker = threading.Thread(target=viewer.handle_request)
                worker.start()
                with socket.create_connection(viewer.server_address, timeout=2) as client:
                    client.sendall(b'GET / HTTP/1.1\r\nHost: ')
                    # Keep every gap well below both the normal inactivity timeout
                    # and the shortened absolute test deadline.
                    for _ in range(20):
                        if not worker.is_alive():
                            break
                        try:
                            client.sendall(b'a')
                        except OSError:
                            break
                        time.sleep(0.03)
                    worker.join(timeout=0.5)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(client.recv(1024), b'')
                self.assertEqual(reader.calls, [])
                # A timed-out client does not prevent the next valid request.
                self.assertEqual(self.request(viewer)[0], 200)

    def test_invalid_configuration_and_clock(self):
        for refresh in (0, 61, True, '30'):
            with self.assertRaises(ValueError):
                EvidenceViewer(Reader(), [HOST], refresh_seconds=refresh)
        with EvidenceViewer(Reader([snapshot()]), [HOST], clock=lambda: '') as viewer:
            self.assertEqual(self.request(viewer)[0], 503)
