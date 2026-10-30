"""Synthetic certificates must support strict mutual TLS on every Python version."""

import ssl
import tempfile
import unittest
from pathlib import Path

from ingestion_test_support import test_pki


class FixturePKITests(unittest.TestCase):
    def test_strict_mutual_tls_for_every_client(self):
        with tempfile.TemporaryDirectory() as directory:
            pki = test_pki(Path(directory))
            for identity in ("client", "other"):
                with self.subTest(identity=identity):
                    client = ssl.create_default_context(cafile=pki["ca"])
                    client.load_cert_chain(*pki[identity][:2])
                    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    server.load_cert_chain(*pki["server"][:2])
                    server.load_verify_locations(pki["ca"])
                    server.verify_mode = ssl.CERT_REQUIRED
                    # Python 3.13 enables this by default; exercise it on older CI too.
                    client.verify_flags |= ssl.VERIFY_X509_STRICT
                    server.verify_flags |= ssl.VERIFY_X509_STRICT
                    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
                    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
                    peers = (
                        client.wrap_bio(client_in, client_out, server_hostname="localhost"),
                        server.wrap_bio(server_in, server_out, server_side=True),
                    )
                    complete = [False, False]
                    for _ in range(10):
                        for index, peer in enumerate(peers):
                            if not complete[index]:
                                try:
                                    peer.do_handshake()
                                    complete[index] = True
                                except ssl.SSLWantReadError:
                                    pass
                        server_in.write(client_out.read())
                        client_in.write(server_out.read())
                        if all(complete):
                            break
                    self.assertEqual(complete, [True, True])
                    self.assertTrue(all(peer.getpeercert() for peer in peers))
