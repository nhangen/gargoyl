"""Explicit security boundaries; no enrollment, command runner or repair API."""

import os
import ssl
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gargoyl.telemetry import (
    MAX_PAYLOAD_BYTES,
    PolicyError,
    decode_snapshot,
    encode_snapshot,
    host_id,
    timestamp,
)


@dataclass(frozen=True)
class CollectionIdentity:
    host_id: str

    def __post_init__(self):
        host_id(self.host_id)

    def authorize(self, action, target):
        if action != "telemetry:write" or target != self.host_id:
            raise PermissionError("collection identity lacks requested authority")


class SpoolCipher:
    """AES-256-GCM with random nonce and host/version authenticated context.

    Supply a provisioned 32-byte key from a separate secret store. Never persist
    the key beside ciphertext. Does not manage keys, files or retention itself.
    """

    def __init__(self, identity, key):
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("a 32-byte spool key is required")
        self.identity = identity
        self._cipher = AESGCM(key)
        self._context = ("gargoyl:spool:v1:" + identity.host_id).encode()

    def seal(self, snapshot):
        payload = encode_snapshot(snapshot)
        self.identity.authorize("telemetry:write", snapshot["host_id"])
        nonce = os.urandom(12)
        return b"GSP1" + nonce + self._cipher.encrypt(nonce, payload, self._context)

    def open(self, encrypted):
        if (
            type(encrypted) is not bytes
            or not 32 <= len(encrypted) <= MAX_PAYLOAD_BYTES + 32
            or encrypted[:4] != b"GSP1"
        ):
            raise PolicyError("invalid encrypted spool record")
        try:
            payload = self._cipher.decrypt(
                encrypted[4:16], encrypted[16:], self._context
            )
        except Exception:
            raise PolicyError("spool authentication failed") from None
        snapshot = decode_snapshot(payload)
        self.identity.authorize("telemetry:write", snapshot["host_id"])
        return snapshot


@dataclass(frozen=True)
class RetentionPolicy:
    max_age_seconds: int = 86400
    max_records: int = 1000

    def __post_init__(self):
        if (
            type(self.max_age_seconds) is not int
            or not 1 <= self.max_age_seconds <= 604800
        ):
            raise ValueError("retention age must be 1..604800 seconds")
        if type(self.max_records) is not int or not 1 <= self.max_records <= 10000:
            raise ValueError("retention count must be 1..10000")

    def select(self, snapshots, now):
        """Validate ALL input; return newest retained snapshots for re-encryption.

        Caller must atomically replace/prune its ciphertext store. Future records
        are excluded; expired records cannot be exported via this policy.
        """
        current = timestamp(now)
        cutoff = current - timedelta(seconds=self.max_age_seconds)
        valid = [decode_snapshot(encode_snapshot(item)) for item in snapshots]
        valid = [
            item
            for item in valid
            if cutoff <= timestamp(item["collected_at"]) <= current
        ]
        return sorted(valid, key=lambda item: timestamp(item["collected_at"]))[
            -self.max_records :
        ]


def export_batch(snapshots, now, policy=None):
    """Explicit default-safe export; no sensitive-data override exists."""
    return [
        encode_snapshot(item)
        for item in (policy or RetentionPolicy()).select(snapshots, now)
    ]


@dataclass(frozen=True)
class TransportConfig:
    endpoint: str
    ca_file: str
    certificate_file: str
    private_key_file: str

    def __post_init__(self):
        url = urlsplit(self.endpoint)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "transport requires an HTTPS endpoint without credentials or query"
            )
        if not all((self.ca_file, self.certificate_file, self.private_key_file)):
            raise ValueError(
                "explicit CA and per-host client certificate/key are required"
            )

    def ssl_context(self):
        context = ssl.create_default_context(cafile=self.ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.certificate_file, self.private_key_file)
        return context


def prepare_transmission(snapshot, identity):
    """Host-bound bytes for an outbound authenticated HTTPS adapter.

    The receiver MUST derive host identity from a verified client certificate,
    match it to this envelope, and reject revoked identities. JSON is not proof.
    """
    payload = encode_snapshot(snapshot)
    identity.authorize("telemetry:write", snapshot["host_id"])
    return payload
