"""Single-owner foreground scheduling over explicitly supplied bounded objects.

No discovery, producer command, credential loader, service installation or worker
pool is provided. The optional CLI validates non-secret configuration only.
"""

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path

from gargoyl.collector_adapters import SOURCE_KINDS
from gargoyl.collector_history import EncryptedHistory
from gargoyl.collector_runtime import CollectorRuntime
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import PolicyError, host_id, timestamp

MAX_CONFIG_BYTES = 4096


def _require(ok):
    if not ok:
        raise PolicyError("invalid foreground configuration or dependencies")


def _positive_budget(value):
    _require(type(value) in (int, float) and math.isfinite(value) and value > 0)
    return value


@dataclass(frozen=True)
class ForegroundConfig:
    host_id: str
    sources: tuple[str, ...]
    interval_seconds: float = 30

    def __post_init__(self):
        host_id(self.host_id)
        _require(
            type(self.sources) is tuple and 1 <= len(self.sources) <= len(SOURCE_KINDS)
        )
        _require(
            all(type(kind) is str and kind in SOURCE_KINDS for kind in self.sources)
        )
        _require(len(set(self.sources)) == len(self.sources))
        _require(
            type(self.interval_seconds) in (int, float)
            and math.isfinite(self.interval_seconds)
            and 1 <= self.interval_seconds <= 60
        )

    @classmethod
    def from_mapping(cls, mapping):
        _require(
            type(mapping) is dict
            and set(mapping) == {"version", "host_id", "sources", "interval_seconds"}
        )
        _require(type(mapping["version"]) is int and mapping["version"] == 1)
        _require(type(mapping["sources"]) is list)
        return cls(
            mapping["host_id"], tuple(mapping["sources"]), mapping["interval_seconds"]
        )


@dataclass(frozen=True)
class ForegroundOutcome:
    status: str
    reason: str
    collections: int = 0
    deliveries: int = 0
    retries: int = 0


def _dependencies(config, acquisition, transport, monotonic_clock, stop_event):
    _require(isinstance(config, ForegroundConfig))
    _require(callable(getattr(acquisition, "acquire", None)))
    _require(callable(getattr(transport, "send", None)))
    acquisition_budget = _positive_budget(
        getattr(acquisition, "total_timeout_seconds", None)
    )
    transport_budget = _positive_budget(
        getattr(transport, "total_timeout_seconds", None)
    )
    _require(transport_budget <= 30)
    _require(math.isfinite(len(config.sources) * acquisition_budget + transport_budget))
    _require(callable(monotonic_clock))
    _require(callable(getattr(stop_event, "is_set", None)))
    _require(callable(getattr(stop_event, "wait", None)))


class _ClockError(Exception):
    pass


def run_foreground(config, *, runtime, acquisition, monotonic_clock, stop_event):
    """Run borrowed runtime/acquisition on the calling thread until stopped.

    Calls must honor their declared total budgets. A lying callback cannot be
    made bounded without a separate execution boundary, intentionally not added
    here. No borrowed object is closed. Runtime TTL must remain fixed at 60.
    """
    _dependencies(
        config,
        acquisition,
        getattr(runtime, "transport", None),
        monotonic_clock,
        stop_event,
    )
    _require(
        getattr(getattr(runtime, "identity", None), "host_id", None) == config.host_id
    )
    _require(getattr(runtime, "ttl", None) == 60)
    _require(callable(getattr(runtime, "collect_acquired", None)))
    _require(callable(getattr(runtime, "deliver_tick", None)))
    collections = deliveries = retries = 0
    last_clock = None

    def clock():
        nonlocal last_clock
        try:
            value = monotonic_clock()
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value < 0
                or (last_clock is not None and value < last_clock)
            ):
                raise _ClockError()
            last_clock = value
            return value
        except Exception:
            raise _ClockError() from None

    def outcome(status, reason):
        return ForegroundOutcome(status, reason, collections, deliveries, retries)

    try:
        next_collection = clock()
        while not stop_event.is_set():
            now = clock()
            collected = False
            if now >= next_collection:
                results = {}
                for kind in config.sources:
                    if stop_event.is_set():
                        return outcome("stopped", "stop_requested")
                    try:
                        result = acquisition.acquire(kind, stop_event=stop_event)
                    except (Exception, KeyboardInterrupt):
                        # Without a returned cleanup receipt, containment is unknown.
                        return outcome(
                            "incomplete_shutdown", "acquisition_did_not_complete"
                        )
                    if getattr(result, "cleanup_complete", None) is not True:
                        return outcome(
                            "incomplete_shutdown", "acquisition_cleanup_incomplete"
                        )
                    results[kind] = result
                    clock()
                if stop_event.is_set():
                    return outcome("stopped", "stop_requested")
                try:
                    persisted = runtime.collect_acquired(results)
                    if type(persisted) is not dict:
                        return outcome("failed", "invalid_collection_outcome")
                except Exception:
                    return outcome("failed", "collection_failed")
                results.clear()
                collections += 1
                collected = True
            if stop_event.is_set():
                return outcome("stopped", "stop_requested")
            try:
                delivery = runtime.deliver_tick()
            except Exception:
                return outcome("failed", "delivery_state_failed")
            if delivery == "sent":
                deliveries += 1
            elif delivery == "retry":
                retries += 1
            elif delivery != "idle":
                return outcome("failed", "invalid_delivery_outcome")
            now = clock()
            if stop_event.is_set():
                return outcome("stopped", "stop_requested")
            if collected:
                # Advance to the first future slot, never replay elapsed slots.
                skipped = (
                    math.floor((now - next_collection) / config.interval_seconds) + 1
                )
                next_collection += skipped * config.interval_seconds
                if not math.isfinite(next_collection) or next_collection <= now:
                    raise _ClockError()
            delay = min(1.0, max(0.0, next_collection - now))
            try:
                stop_event.wait(delay)
            except Exception:
                return outcome("failed", "wait_failed")
        return outcome("stopped", "stop_requested")
    except _ClockError:
        return outcome("failed", "invalid_monotonic_clock")
    except KeyboardInterrupt:
        return outcome("stopped", "interrupted")
    except Exception:
        return outcome("failed", "scheduler_failed")


def run_configured(
    config,
    *,
    identity,
    cipher,
    transport,
    acquisition,
    spool_directory,
    wall_clock,
    monotonic_clock,
    stop_event,
    policy=None,
):
    """Compose and own history/runtime; all supplied capabilities stay borrowed.

    Validate before opening storage. No key/certificate/executable configuration
    is loaded. The caller must authorize and construct acquisition and transport.
    """
    _dependencies(config, acquisition, transport, monotonic_clock, stop_event)
    _require(
        isinstance(identity, CollectionIdentity) and identity.host_id == config.host_id
    )
    _require(
        isinstance(cipher, SpoolCipher) and cipher.identity.host_id == config.host_id
    )
    _require(callable(wall_clock))
    policy = RetentionPolicy() if policy is None else policy
    _require(isinstance(policy, RetentionPolicy))
    # Fail before filesystem effects if the normalized runtime dependency is absent.
    _require(callable(getattr(CollectorRuntime, "collect_acquired", None)))
    try:
        now = wall_clock()
        timestamp(now)
        monotonic = monotonic_clock()
        _require(
            type(monotonic) in (int, float)
            and math.isfinite(monotonic)
            and monotonic >= 0
        )
    except Exception:
        raise PolicyError("invalid foreground startup clock") from None
    if stop_event.is_set():
        return ForegroundOutcome("stopped", "stop_requested")
    try:
        history = EncryptedHistory(spool_directory, cipher, policy, now)
    except Exception:
        return ForegroundOutcome("failed", "history_initialization_failed")
    result = ForegroundOutcome("failed", "runtime_initialization_failed")
    try:
        runtime = CollectorRuntime(
            identity,
            history,
            transport,
            wall_clock=wall_clock,
            monotonic_clock=monotonic_clock,
            interval_seconds=config.interval_seconds,
            ttl=60,
        )
        result = run_foreground(
            config,
            runtime=runtime,
            acquisition=acquisition,
            monotonic_clock=monotonic_clock,
            stop_event=stop_event,
        )
    except KeyboardInterrupt:
        result = ForegroundOutcome("stopped", "interrupted")
    except Exception:
        result = ForegroundOutcome("failed", "runtime_initialization_failed")
    finally:
        try:
            history.close()
        except Exception:
            result = ForegroundOutcome(
                "incomplete_shutdown",
                "history_close_failed",
                result.collections,
                result.deliveries,
                result.retries,
            )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate non-secret foreground configuration; never run acquisition."
    )
    parser.add_argument("--check-config", required=True, metavar="JSON_FILE")
    arguments = parser.parse_args(argv)
    try:
        with Path(arguments.check_config).open("rb") as stream:
            payload = stream.read(MAX_CONFIG_BYTES + 1)
        _require(len(payload) <= MAX_CONFIG_BYTES)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                _require(key not in result)
                result[key] = value
            return result

        ForegroundConfig.from_mapping(
            json.loads(payload.decode("utf-8"), object_pairs_hook=unique)
        )
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("Foreground configuration unavailable or invalid.", file=sys.stderr)
        return 2
    print("Foreground configuration valid. No acquisition started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
