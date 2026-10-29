"""Local integration HTTPS receiver. No public hosting or credential provisioning.

The service receives certificate bytes only from the verified TLS socket. This
single-request-at-a-time server intentionally binds only to localhost. Application
hosting, certificate lifecycle and production availability are separate work.
"""

import math
import re
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

from gargoyl.telemetry import MAX_PAYLOAD_BYTES, PolicyError


class _Receiver(HTTPServer):
    def __init__(self, address, handler, context, timeout):
        self._tls_context = context
        self._request_timeout = timeout
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self._request_timeout)
        try:
            return self._tls_context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        # Never let stdlib traceback logging expose peer addresses or payloads.
        pass


def make_ingestion_server(
    service,
    *,
    ca_file,
    certificate_file,
    private_key_file,
    clock,
    host="localhost",
    port=0,
    timeout=2,
):
    """Return an unstarted local HTTPS server with explicit mTLS trust and clock.

    Caller owns serve_forever/shutdown/server_close and EvidenceStore.close.
    Production listeners and service installation are deliberately unsupported.
    """
    if host != "localhost":
        raise ValueError("integration receiver binds only to localhost")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("invalid listener port")
    if (
        type(timeout) not in (int, float)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 10
    ):
        raise ValueError("invalid request timeout")
    if not callable(clock):
        raise ValueError("explicit clock required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(certificate_file, private_key_file)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _reply(self, status):
            self.close_connection = True
            self.send_response_only(status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def send_error(self, code, message=None, explain=None):
            self._reply(code)

        def do_POST(self):
            if self.path != "/v1/snapshots":
                self._reply(404)
                return
            lengths = self.headers.get_all("Content-Length", [])
            content_types = self.headers.get_all("Content-Type", [])
            if (
                len(lengths) != 1
                or len(content_types) != 1
                or content_types[0] != "application/json"
                or any(
                    name in self.headers
                    for name in ("Transfer-Encoding", "Content-Encoding", "Expect")
                )
                or re.fullmatch(r"[0-9]{1,5}", lengths[0]) is None
            ):
                self._reply(400)
                return
            size = int(lengths[0])
            if not 1 <= size <= MAX_PAYLOAD_BYTES:
                self._reply(413)
                return
            payload = self.rfile.read(size)
            if len(payload) != size:
                self._reply(400)
                return
            try:
                peer = self.connection.getpeercert(binary_form=True)
                accepted = service.accept(payload, peer, now=clock())
            except PermissionError:
                self._reply(403)
            except PolicyError:
                self._reply(400)
            except Exception:
                self._reply(503)
            else:
                self._reply(204 if accepted is True else 503)

        def do_GET(self):
            self._reply(405)

    return _Receiver((host, port), Handler, context, timeout)
