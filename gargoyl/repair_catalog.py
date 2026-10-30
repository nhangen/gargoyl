"""Signed artifact verification and conservative dry-run planning; no execution."""

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gargoyl.repair_contract import (
    MAX_EVIDENCE_RECORDS,
    RUNBOOK_IDS,
    RepairPlan,
    canonical,
    digest,
    enum,
    integer,
    key_id,
    manifest_bytes,
    parse,
    require,
    validate_proof,
)
from gargoyl.telemetry import (
    PolicyError,
    effective_state,
    host_id,
    timestamp,
    validate_snapshot,
)

SIGNING_CONTEXT = b"gargoyl:repair:manifest:v1\x00"
_REQUIRED = MappingProxyType({
    "status_refresh": (),
    "diagnostics_capture": (),
    "drained_provider_restart": ("in_flight_work", "drain_acknowledgement"),
    "model_load_retry": ("in_flight_work", "selected_model", "model_memory_requirement"),
    "stale_state_reconciliation": ("reconciliation_scope",),
})


@dataclass(frozen=True)
class VerifiedRunbook:
    """Artifact proof container; construction/class identity does not establish trust."""

    payload: bytes

    def __post_init__(self):
        object.__setattr__(self, "payload", canonical(validate_proof(parse(getattr(self, "payload", None)))))

    def as_dict(self):
        return validate_proof(parse(getattr(self, "payload", None)))

    @property
    def digest(self):
        return hashlib.sha256(manifest_bytes(self.as_dict()["manifest"])).hexdigest()


class RunbookCatalog:
    """Explicit pinned artifact trust; no signer discovery or user authorization.

    trusted_keys: {key_id: raw 32-byte Ed25519 public key}, at most 16.
    allowed_versions: frozenset[(runbook_id, positive_version, manifest_sha256)],
    at most 64. Copies both; replacement requires a new catalog.
    """

    def __init__(self, *, trusted_keys, allowed_versions):
        require(type(trusted_keys) is dict and 1 <= len(trusted_keys) <= 16)
        keys = {}
        for name, public in trusted_keys.items():
            key_id(name)
            require(type(public) is bytes and len(public) == 32)
            keys[name] = Ed25519PublicKey.from_public_bytes(public)
        require(type(allowed_versions) is frozenset and 1 <= len(allowed_versions) <= 64)
        for entry in allowed_versions:
            require(type(entry) is tuple and len(entry) == 3)
            enum(entry[0], RUNBOOK_IDS)
            integer(entry[1], 1, 2**31 - 1)
            digest(entry[2])
        self._keys = MappingProxyType(keys)
        self._allowed = frozenset(allowed_versions)

    def verify_runbook(self, payload, signature, *, key_id):
        manifest = parse(payload)
        canonical_manifest = manifest_bytes(manifest)
        require(type(key_id) is str and key_id in self._keys)
        require(type(signature) is bytes and len(signature) == 64)
        checksum = hashlib.sha256(canonical_manifest).hexdigest()
        require((manifest["runbook_id"], manifest["version"], checksum) in self._allowed)
        try:
            self._keys[key_id].verify(signature, SIGNING_CONTEXT + canonical_manifest)
        except InvalidSignature:
            raise PolicyError("runbook signature rejected") from None
        return VerifiedRunbook(canonical({"manifest": manifest, "key_id": key_id,
                                          "signature": signature.hex()}))

    def validate_runbook(self, runbook):
        require(type(runbook) is VerifiedRunbook)
        proof = runbook.as_dict()
        return self.verify_runbook(manifest_bytes(proof["manifest"]),
                                   bytes.fromhex(proof["signature"]), key_id=proof["key_id"])

    def plan(self, runbook, target_host, evidence, *, now):
        proof = self.validate_runbook(runbook).as_dict()
        host_id(target_host)
        current = timestamp(now)
        require(type(evidence) in (list, tuple) and len(evidence) <= MAX_EVIDENCE_RECORDS)
        records = []
        fresh = bool(evidence)
        observations = {}
        for snapshot in evidence:
            copy = validate_snapshot(snapshot)
            require(copy["host_id"] == target_host)
            fresh = fresh and timestamp(copy["collected_at"]) <= current
            for name, field in copy["fields"].items():
                fresh = fresh and effective_state(field, now) == "observed"
                # Preserve contradictions rather than selecting a winning report.
                slot = (name, field["source"], timestamp(field["timestamp"]))
                encoded = canonical(field)
                if slot in observations and observations[slot] != encoded:
                    fresh = False
                observations[slot] = encoded
            records.append(copy)
        # Canonical order and exact-dedup only. Original conflicting reports survive.
        records = [parse(item) for item in sorted({canonical(item) for item in records})]
        required = _REQUIRED[proof["manifest"]["runbook_id"]]
        checks = [{"check_id": "artifact_verified", "state": "passed", "required": True},
                  {"check_id": "evidence_fresh", "state": "passed" if fresh else "unknown",
                   "required": bool(required)}]
        checks.extend({"check_id": name, "state": "blocked", "required": True} for name in required)
        try:
            expiry = (current + timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
        except OverflowError:
            raise PolicyError("invalid repair plan time") from None
        return RepairPlan(canonical({
            "schema_version": 1, "target_host": target_host, "runbook": proof,
            "evidence": records, "evaluated_at": now, "expires_at": expiry,
            "checks": checks, "blocked": bool(required),
        }))

    def validate_plan(self, plan, *, now):
        require(type(plan) is RepairPlan)
        value = plan.as_dict()
        require(timestamp(value["evaluated_at"]) <= timestamp(now) < timestamp(value["expires_at"]))
        expected = self.plan(VerifiedRunbook(canonical(value["runbook"])),
                             value["target_host"], value["evidence"], now=value["evaluated_at"])
        require(expected.payload == canonical(value))
        return expected
