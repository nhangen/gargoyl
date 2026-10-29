"""Loopback-only, read-only HTTP viewer for a structurally supplied evidence store.

Use the reader's documented thread-safety contract. No background thread, credential
provisioning, TLS termination, ingestion endpoint, or repair action is provided.
"""
import io
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from gargoyl.dashboard import render_dashboard
from gargoyl.telemetry import host_id, timestamp

HEADER_DEADLINE_SECONDS = 5


class _DeadlineReader(io.RawIOBase):
    """Bound header reads by elapsed time, including clients that drip bytes."""

    def __init__(self, connection):
        self.connection = connection
        self.deadline = time.monotonic() + HEADER_DEADLINE_SECONDS

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request header deadline exceeded")
        self.connection.settimeout(min(5, remaining))
        return self.connection.recv_into(buffer)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class EvidenceViewer(HTTPServer):
    """Serve GET / on numeric IPv4 loopback only; caller owns store lifecycle.

    reader.snapshots(now=utc_string) must return bounded, consistent detached v1
    snapshots or raise on any read failure. expected_hosts is independent inventory.
    The caller drives serve_forever/handle_request, stops/joins listener threads,
    then closes viewer and reader. EvidenceStore permits locked cross-thread reads.
    """

    allow_reuse_address = False

    def __init__(self, reader, expected_hosts, *, clock=utc_now, port=0, refresh_seconds=30):
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid viewer port")
        if type(refresh_seconds) is not int or not 1 <= refresh_seconds <= 60:
            raise ValueError("invalid viewer refresh interval")
        if not callable(clock) or not callable(getattr(reader, 'snapshots', None)):
            raise ValueError("invalid viewer dependencies")
        self.reader = reader
        self.expected_hosts = tuple(host_id(value) for value in expected_hosts)
        self.clock = clock
        self.refresh_seconds = refresh_seconds
        super().__init__(('127.0.0.1', port), _Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def handle_error(self, request, client_address):
        # Do not log peer addresses, paths, storage errors, or evidence.
        pass


class _Handler(BaseHTTPRequestHandler):
    server_version = 'Gargoyl'
    sys_version = ''

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(_DeadlineReader(self.connection))

    def log_message(self, format, *args):
        pass

    def _respond(self, status, body):
        payload = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True
        if self.command != 'HEAD':
            self.wfile.write(payload)

    def send_error(self, code, message=None, explain=None):
        # Base parser errors must not echo request text or its default HTML page.
        self._respond(code, '<!doctype html><title>Request rejected</title><p>Request rejected.</p>')

    def do_GET(self):
        authority = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get_all('Host') != [authority]:
            self.send_error(403)
            return
        origins = self.headers.get_all('Origin')
        if origins is not None and origins != ['http://' + authority]:
            self.send_error(403)
            return
        if self.path != '/':
            self.send_error(404)
            return
        # Header reads may have shortened the socket timeout. Restore the bounded
        # response-write timeout after parsing; no request body is consumed.
        self.connection.settimeout(5)
        try:
            now = self.server.clock()
            timestamp(now)
            page = render_dashboard(self.server.reader.snapshots(now=now), self.server.expected_hosts, now)
            page = page.replace('Read-only snapshot view. Regenerate after collection and at least every minute.',
                                'Read-only stored evidence. This page refreshes automatically; evaluation time below identifies the current report.')
            status = 200
        except Exception:
            # Never turn a failed read into an empty successful fleet, or serve a
            # cached healthy page. Do not expose exception strings or file paths.
            page = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Evidence unavailable</title><h1>Evidence unavailable</h1><p>Storage or evaluation failed. Fleet state is unknown. No successful report is available. This page will retry automatically.</p></html>'
            status = 503
        refresh = f'<meta http-equiv="refresh" content="{self.server.refresh_seconds}">'
        self._respond(status, page.replace('<title>', refresh + '<title>', 1))

    do_HEAD = do_GET
