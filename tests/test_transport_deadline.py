"""Synthetic local TLS and fault-injection tests; no configured credentials."""
import contextlib
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ingestion_test_support import test_pki

from gargoyl.collector import collect
from gargoyl.collector_history import (
    MAX_RESPONSE_HEADER_BYTES,
    EncryptedHistory,
    OutboundHTTPS,
)
from gargoyl.collector_runtime import CollectorRuntime
from gargoyl.security import (
    CollectionIdentity,
    RetentionPolicy,
    SpoolCipher,
    TransportConfig,
)

HOST = '00000000-0000-4000-8000-000000000001'
NOW = '2026-01-01T00:00:00Z'


class TransportDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pki = test_pki(self.root)
        self.identity = CollectionIdentity(HOST)
        self.data = collect(HOST, NOW, {})

    def config(self, port, hostname='localhost'):
        return TransportConfig(f'https://{hostname}:{port}/v1/snapshots', self.pki['ca'],
                               *self.pki['client'][:2])

    @contextlib.contextmanager
    def peer(self, response=b'HTTP/1.1 204 No Content\r\n\r\n', *, drip=False, handshake_stall=False, drip_prefix=0):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(2)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*self.pki['server'][:2])
        context.load_verify_locations(self.pki['ca'])
        context.verify_mode = ssl.CERT_REQUIRED
        stop = threading.Event()
        requests = []
        errors = []

        def serve():
            try:
                raw, _ = listener.accept()
                with raw:
                    raw.settimeout(2)
                    if handshake_stall:
                        stop.wait(1)
                        return
                    with context.wrap_socket(raw, server_side=True) as channel:
                        request = bytearray()
                        while not request.endswith(b'\r\n\r\n'):
                            byte = channel.recv(1)
                            if not byte:
                                return
                            request.extend(byte)
                        length = int(next(line.split(b':', 1)[1] for line in request.split(b'\r\n')
                                          if line.lower().startswith(b'content-length:')))
                        remaining = length
                        while remaining:
                            chunk = channel.recv(remaining)
                            if not chunk:
                                return
                            remaining -= len(chunk)
                        requests.append(bytes(request))
                        if drip:
                            channel.sendall(response[:drip_prefix])
                            for byte in response[drip_prefix:]:
                                channel.sendall(bytes([byte]))
                                if stop.wait(0.025):
                                    break
                        else:
                            channel.sendall(response)
            except OSError:
                # Timeout/early-close and failed verification intentionally abort peers.
                pass
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield listener.getsockname()[1], requests
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_timely_mtls_ack_statuses_and_original_host(self):
        for status, expected in ((200, True), (201, True), (204, True), (202, False), (302, False), (500, False)):
            with self.subTest(status=status), self.peer(f'HTTP/1.1 {status} Result\r\nContent-Length: 0\r\n\r\n'.encode()) as (port, requests):
                sender = OutboundHTTPS(self.config(port), self.identity)
                with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
                    self.assertEqual(sender.send(self.data), expected)
                self.assertIn(f'Host: localhost:{port}\r\n'.encode(), requests[0])

    def test_dripping_status_and_headers_cannot_extend_deadline(self):
        for response in (b'HTTP/1.1 204 No Content\r\n\r\n',
                         b'HTTP/1.1 204 No Content\r\nX-Slow: ' + b'a' * 100 + b'\r\n\r\n'):
            with self.subTest(response_length=len(response)), self.peer(response, drip=True, drip_prefix=0 if len(response) < 40 else 32) as (port, _):
                sender = OutboundHTTPS(self.config(port), self.identity, total_timeout_seconds=0.18)
                started = time.monotonic()
                with self.assertRaisesRegex(TimeoutError, '^outbound deadline exceeded$'):
                    sender.send(self.data)
                self.assertLess(time.monotonic() - started, 0.8)

    def test_stalled_tls_handshake_is_bounded(self):
        with self.peer(handshake_stall=True) as (port, _):
            sender = OutboundHTTPS(self.config(port), self.identity, total_timeout_seconds=0.15)
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                sender.send(self.data)
            self.assertLess(time.monotonic() - started, 0.8)

    def test_explicit_address_never_disables_hostname_verification(self):
        with self.peer() as (port, _):
            sender = OutboundHTTPS(self.config(port, 'wrong.synthetic.invalid'), self.identity,
                                   connect_address='127.0.0.1')
            with self.assertRaisesRegex(OSError, '^outbound transmission failed$'):
                sender.send(self.data)

    def test_invalid_configuration_precedes_trust_and_network(self):
        config = self.config(443, 'synthetic.invalid')
        for options in ({}, {'connect_address': 'another.invalid'}, {'total_timeout_seconds': 0},
                        {'total_timeout_seconds': 31}, {'total_timeout_seconds': True},
                        {'total_timeout_seconds': float('nan')}, {'connect_address': 'fe80::1%zone'}):
            with self.subTest(options=options), patch.object(TransportConfig, 'ssl_context') as trust, patch('socket.socket') as network:
                with self.assertRaises(ValueError):
                    OutboundHTTPS(config, self.identity, **options)
                trust.assert_not_called()
                network.assert_not_called()

    def test_header_limits_strict_framing_and_no_body_read(self):
        sender = OutboundHTTPS(self.config(443), self.identity)
        responses = [b'HTTP/1.1 204 OK\r\n', b'HTTP/1.1 204 OK\n\n',
                     b'HTTP/1.1 204 OK\r\nX: ' + b'a' * MAX_RESPONSE_HEADER_BYTES,
                     b'HTTP/1.1 204 OK\r\n' + b'X: a\r\n' * 101 + b'\r\n',
                     b'HTTP/1.1 204 OK\r\n folded\r\n\r\n',
                     b'HTTP/1.1 204 OK\r\nContent-Length: 1\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n']
        for raw in responses:
            channel = Mock()
            channel.recv.side_effect = [bytes([b]) for b in raw] + [b'']
            self.assertFalse(sender._acknowledged(channel, time.monotonic() + 5))
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n'
        channel = Mock()
        channel.recv.side_effect = [bytes([b]) for b in raw]  # reading any body raises
        self.assertTrue(sender._acknowledged(channel, time.monotonic() + 5))
        self.assertEqual(channel.recv.call_count, len(raw))

    def test_one_budget_shared_by_connect_handshake_write_and_late_ack(self):
        with patch('gargoyl.collector_history.time.monotonic') as clock, patch('socket.socket') as make_socket:
            current = [0.0]
            clock.side_effect = lambda: current[0]
            sender = OutboundHTTPS(self.config(443), self.identity, total_timeout_seconds=1)
            raw, channel = Mock(), Mock()
            make_socket.return_value = raw
            sender.context = Mock()
            sender.context.wrap_socket.return_value = channel
            raw.connect.side_effect = lambda address: current.__setitem__(0, 0.4)
            channel.do_handshake.side_effect = lambda: current.__setitem__(0, 0.7)
            channel.sendall.side_effect = lambda payload: current.__setitem__(0, 0.9)
            response = iter(b'HTTP/1.1 204 OK\r\n\r\n')

            def receive(count):
                byte = bytes([next(response)])
                if byte == b'\n':
                    current[0] = 1.01
                return byte

            channel.recv.side_effect = receive
            with self.assertRaises(TimeoutError):
                sender.send(self.data)
            self.assertAlmostEqual(channel.settimeout.call_args_list[0].args[0], 0.6)
            self.assertAlmostEqual(channel.settimeout.call_args_list[1].args[0], 0.3)
            channel.close.assert_called_once()

    def test_complete_headers_final_byte_after_deadline_never_acknowledged(self):
        sender = OutboundHTTPS(self.config(443), self.identity)
        response = b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n'
        current = [0.5]
        received = bytearray()
        channel = Mock()

        def receive(count):
            self.assertEqual(count, 1)
            byte = response[len(received):len(received) + 1]
            received.extend(byte)
            if len(received) == len(response):
                current[0] = 1.01
            return byte

        channel.recv.side_effect = receive
        with patch('gargoyl.collector_history.time.monotonic', side_effect=lambda: current[0]):
            with self.assertRaisesRegex(TimeoutError, '^outbound deadline exceeded$'):
                sender._acknowledged(channel, deadline=1.0)
        self.assertEqual(bytes(received), response)
        self.assertEqual(channel.recv.call_count, len(response))

    def test_timeout_retains_history_then_collection_and_delivery_resume(self):
        history = EncryptedHistory(self.root / 'history', SpoolCipher(self.identity, os.urandom(32)), RetentionPolicy(), NOW)
        self.addCleanup(history.close)
        wall, mono = [NOW], [0]
        with self.peer(drip=True) as (port, _):
            sender = OutboundHTTPS(self.config(port), self.identity, total_timeout_seconds=0.15)
            runtime = CollectorRuntime(self.identity, history, sender, wall_clock=lambda: wall[0], monotonic_clock=lambda: mono[0])
            runtime.collect_tick({})
            self.assertEqual(runtime.deliver_tick(), 'retry')
            self.assertEqual(len(history.pending(wall[0])), 1)
        wall[0], mono[0] = '2026-01-01T00:00:30Z', 30
        runtime.collect_tick({})
        self.assertEqual(len(history.pending(wall[0])), 2)
        with self.peer() as (port, _):
            runtime.transport = OutboundHTTPS(self.config(port), self.identity)
            self.assertEqual(runtime.deliver_tick(), 'sent')
        self.assertEqual(len(history.pending(wall[0])), 1)
