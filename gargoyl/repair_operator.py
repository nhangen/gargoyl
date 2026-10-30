"""Explicit operator key verification; no enrollment, key loader or click claims."""

import threading
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gargoyl.repair_contract import (
    RUNBOOK_IDS,
    RepairConfirmation,
    RepairPlan,
    canonical,
    enum,
    exact,
    integer,
    key_id,
    parse,
    require,
    validate_confirmation,
)
from gargoyl.telemetry import PolicyError, host_id, timestamp

REPAIR_INTENT_CONTEXT = b"gargoyl:operator:repair:v1\x00"
READ_INTENT_CONTEXT = b"gargoyl:operator:read:v1\x00"
MAX_OPERATOR_KEYS = 64
MAX_OPERATOR_HOSTS = 16


def _hosts(value):
    require(type(value) is frozenset and len(value) <= MAX_OPERATOR_HOSTS)
    for item in value:
        host_id(item)
    return value


@dataclass(frozen=True)
class OperatorPrincipal:
    actor_id: str
    repair_grants: frozenset = frozenset()
    evidence_hosts: frozenset = frozenset()
    audit_hosts: frozenset = frozenset()

    def __post_init__(self):
        host_id(self.actor_id)
        require(type(self.repair_grants) is frozenset
                and len(self.repair_grants) <= MAX_OPERATOR_HOSTS * len(RUNBOOK_IDS))
        hosts = set(_hosts(self.evidence_hosts)) | set(_hosts(self.audit_hosts))
        for pair in self.repair_grants:
            require(type(pair) is tuple and len(pair) == 2)
            hosts.add(host_id(pair[0]))
            enum(pair[1], RUNBOOK_IDS)
        require(len(hosts) <= MAX_OPERATOR_HOSTS)


def _principal(value):
    require(type(value) is OperatorPrincipal)
    return OperatorPrincipal(getattr(value, "actor_id", None),
                             getattr(value, "repair_grants", None),
                             getattr(value, "evidence_hosts", None),
                             getattr(value, "audit_hosts", None))


@dataclass(frozen=True)
class OperatorKey:
    public_key: bytes
    principal: OperatorPrincipal

    def __post_init__(self):
        require(type(self.public_key) is bytes and len(self.public_key) == 32)
        object.__setattr__(self, "principal", _principal(self.principal))


def _key(value):
    require(type(value) is OperatorKey)
    return OperatorKey(getattr(value, "public_key", None), getattr(value, "principal", None))


@dataclass(frozen=True, init=False)
class OperatorRegistry:
    """Detached immutable key-to-principal registry. Replace to change/revoke grants."""

    _entries: tuple

    def __init__(self, keys_by_id):
        require(type(keys_by_id) is dict and 1 <= len(keys_by_id) <= MAX_OPERATOR_KEYS)
        copied = {}
        public_keys = set()
        for name, value in keys_by_id.items():
            key_id(name)
            value = _key(value)
            require(value.public_key not in public_keys)
            public_keys.add(value.public_key)
            copied[name] = value
        object.__setattr__(self, "_entries", tuple(sorted(copied.items())))

    def _validated(self):
        require(type(self) is OperatorRegistry)
        entries = getattr(self, "_entries", None)
        require(type(entries) is tuple and 1 <= len(entries) <= MAX_OPERATOR_KEYS)
        copied = {}
        for entry in entries:
            require(type(entry) is tuple and len(entry) == 2)
            name, value = entry
            key_id(name)
            require(name not in copied)
            copied[name] = _key(value)
        return OperatorRegistry(copied)

    def lookup(self, name):
        key_id(name)
        entries = dict(self._validated()._entries)
        require(name in entries)
        return entries[name]


def _proof(proof):
    exact(proof, "key_id signature")
    key_id(proof["key_id"])
    require(type(proof["signature"]) is bytes and len(proof["signature"]) == 64)
    return dict(proof)


def _read_request(request):
    exact(request, "schema_version actor_id request_id issued_at expires_at")
    integer(request["schema_version"], 1, 1)
    host_id(request["actor_id"])
    host_id(request["request_id"])
    start, end = timestamp(request["issued_at"]), timestamp(request["expires_at"])
    require(0 < (end - start).total_seconds() <= 60)
    return parse(canonical(request))


def repair_intent_bytes(audience, confirmation):
    """Bytes to sign externally. This helper does not sign or grant authority."""
    host_id(audience)
    require(type(confirmation) is RepairConfirmation)
    confirmation = RepairConfirmation(getattr(confirmation, "payload", None))
    return REPAIR_INTENT_CONTEXT + canonical({"audience": audience, "confirmation": confirmation.as_dict()})


def read_intent_bytes(audience, request):
    """Read-only intent uses a different context from repair and runbook signatures."""
    host_id(audience)
    return READ_INTENT_CONTEXT + canonical({"audience": audience, "request": _read_request(request)})


@dataclass(frozen=True)
class OperatorReadScope:
    """Verified grant snapshot, not a serializable credential or durable authority."""

    actor_id: str
    evidence_hosts: frozenset
    audit_hosts: frozenset
    expires_at: str

    def __post_init__(self):
        host_id(self.actor_id)
        require(len(_hosts(self.evidence_hosts) | _hosts(self.audit_hosts)) <= MAX_OPERATOR_HOSTS)
        timestamp(self.expires_at)


class _Verification:
    def __init__(self, proof, *, registry_provider, audience, wall_clock):
        self._proof = _proof(proof)
        host_id(audience)
        require(callable(registry_provider) and callable(wall_clock))
        self._provider, self._audience, self._wall_clock = registry_provider, audience, wall_clock
        self._lock = threading.Lock()
        self._last_seen = None

    def _verify(self, message):
        proof = _proof(self._proof)
        registry = self._provider()
        require(type(registry) is OperatorRegistry)
        entry = registry.lookup(proof["key_id"])
        try:
            Ed25519PublicKey.from_public_bytes(entry.public_key).verify(proof["signature"], message)
        except InvalidSignature:
            raise PolicyError("operator authorization unavailable") from None
        return entry.principal

    def _now(self):
        now = self._wall_clock()
        current = timestamp(now)
        require(self._last_seen is None or current >= self._last_seen)
        self._last_seen = current
        return now


class OperatorAuthorization(_Verification):
    def authorize(self, plan, confirmation):
        """Return None only for a current exact repair grant and signed intent.

        Runtime still verifies catalog, preflight and durable one-use click claim.
        Every call rereads the trusted registry; no authentication result is cached.
        """
        try:
            with self._lock:
                require(type(plan) is RepairPlan and type(confirmation) is RepairConfirmation)
                plan = RepairPlan(getattr(plan, "payload", None))
                confirmation = RepairConfirmation(getattr(confirmation, "payload", None))
                principal = self._verify(repair_intent_bytes(self._audience, confirmation))
                now = self._now()  # after provider/crypto work, not before a slow callback
                confirmation = validate_confirmation(confirmation, plan, now=now).as_dict()
                require(confirmation["actor_id"] == principal.actor_id)
                require((confirmation["target_host"], confirmation["runbook_id"])
                        in principal.repair_grants)
                return None
        except Exception:
            raise PolicyError("operator authorization unavailable") from None


class OperatorReadAuthorization(_Verification):
    def __init__(self, request, proof, *, registry_provider, audience, wall_clock):
        super().__init__(proof, registry_provider=registry_provider, audience=audience, wall_clock=wall_clock)
        self._request = _read_request(request)

    def read_scope(self):
        """Reverify current key/grants/expiry; read proof never grants execution."""
        try:
            with self._lock:
                request = _read_request(self._request)
                principal = self._verify(read_intent_bytes(self._audience, request))
                current = timestamp(self._now())
                require(timestamp(request["issued_at"]) <= current < timestamp(request["expires_at"]))
                require(request["actor_id"] == principal.actor_id)
                return OperatorReadScope(principal.actor_id, principal.evidence_hosts,
                                         principal.audit_hosts, request["expires_at"])
        except Exception:
            raise PolicyError("operator authorization unavailable") from None
