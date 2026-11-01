"""Explicit owner-local diagnostic composition for pinned Darkbloom 0.10.5/0.10.6 state.

No status/doctor command, credential/config discovery or lifecycle invocation.
Only normalized values leave collect(); raw state and log messages are discarded.
"""
import json
import os
import threading
from dataclasses import dataclass

from gargoyl.collector_adapters import AdapterResult
from gargoyl.collector_coordinator_log import (
    CoordinatorLogReader,
    process_birth,
    unknown,
)
from gargoyl.collector_state_file import (
    _epoch,
    _parse,
    _read,
    _require,
    validate_daemon_state_source,
)
from gargoyl.darkbloom_compatibility import SUPPORTED_VERSIONS
from gargoyl.repair_process_identity import MacOSProcessVerifier
from gargoyl.telemetry import effective_state, timestamp


@dataclass(frozen=True)
class DiagnosticCollection:
    result: AdapterResult
    collected_at: str
    log_report: dict


class LocalDiagnostics:
    def __init__(self, *, executable, owner_uid, clock, coordinator_errors=False):
        _require(type(owner_uid) is int and owner_uid == os.getuid()
                 and type(coordinator_errors) is bool and callable(clock))
        self._verifier = MacOSProcessVerifier(expected_owner_uid=owner_uid,
                                              expected_executable=executable)
        self.clock, self.uid = clock, owner_uid
        self._logs = CoordinatorLogReader(executable=executable, clock=clock) if coordinator_errors else None

    def collect(self, source, *, now, stop=None):
        validate_daemon_state_source(source, self.uid)
        timestamp(now)
        stop = stop or threading.Event()
        log = unknown('target_or_state_unverified' if self._logs else 'not_configured', now)
        try:
            payload = _read(source, self.uid, 65536)
            baseline = _parse(payload, now, 60)
            # The shared parser already rejects duplicate keys/nonfinite/deep or
            # malformed JSON. This second decode sees the same bounded bytes.
            state = json.loads(payload)
            readings = dict(baseline.result.readings)
            readings.pop('model_state', None)
            _require(state['version'] in SUPPORTED_VERSIONS)
            process = state.get('process_identity')
            _require(type(process) is dict and set(process) == {'pid', 'start_time_micros'}
                     and type(process['pid']) is int and process['pid'] == state['pid']
                     and type(process['start_time_micros']) is int
                     and 0 < process['start_time_micros'] < 2**64)
            identity = dict(pid=process['pid'], born_us=process['start_time_micros'], owner_uid=self.uid)
            _require(self._verifier(identity))
            birth = process_birth(identity)
            coherent = timestamp(baseline.observed_at) >= birth
            fresh = coherent and (timestamp(now) - timestamp(baseline.observed_at)).total_seconds() <= 60
            if self._logs and coherent and not fresh:
                log = unknown('source_stale', now)
            if self._logs and fresh and not stop.is_set():
                log = self._logs.read(identity, self._verifier, now=now, stop=stop)
            completed = self.clock()
            _require(timestamp(completed) >= timestamp(now) and self._verifier(identity))

            def add(metric, value, at, ttl=60, source="daemon"):
                field = dict(value=value, source=source, timestamp=at,
                             freshness_seconds=ttl, state='observed', sensitivity='safe')
                field['state'] = effective_state(field, completed)
                readings[metric] = field

            # Kernel identity was independently checked at collection completion.
            add('daemon_state', 'running', completed, source='host')
            if not coherent:
                return DiagnosticCollection(AdapterResult(readings, ()), completed, log)
            if state.get('warm_models') or state.get('current_model'):
                add('model_state', 'resident', baseline.observed_at)
            connection = state.get('coordinator_connection')
            try:
                _require(type(connection) is dict and type(connection.get('connected')) is bool)
                since = _epoch(connection.get('since'))
                _require(birth <= timestamp(since) <= timestamp(baseline.observed_at))
                add('coordinator_reachable', 'reachable' if connection['connected'] else 'unreachable',
                    baseline.observed_at)
                if not connection['connected']:
                    add('routing_eligible', 'ineligible', baseline.observed_at)
                else:
                    trust = state.get('trust')
                    _require(type(trust) is dict)
                    at = _epoch(trust.get('received_at'))
                    _require(timestamp(since) <= timestamp(at) <= timestamp(baseline.observed_at))
                    status = trust.get('status')
                    authorization = trust.get('authorization')
                    # Conservative ServingReadiness subset; reasons,
                    # session/machine identifiers, keys and tokens are not interpreted.
                    if status in {'offline', 'untrusted'}:
                        add('routing_eligible', 'ineligible', at)
                    elif status in {'online', 'serving'}:
                        legacy = (type(authorization) is dict and authorization.get('path') == 'legacy'
                                  and type(authorization.get('protocol')) is int
                                  and authorization.get('protocol') == 1)
                        hardware = authorization is None and trust.get('trust_level') == 'hardware'
                        hold = state.get('addon_hold')
                        no_hold = hold is None or (type(hold) is dict and type(hold.get('holds')) is list
                                                   and not hold['holds'])
                        lifecycle = state.get('lifecycle')
                        serving = lifecycle is None or (type(lifecycle) is dict
                                                        and lifecycle.get('outcome') == 'serving')
                        if (legacy or hardware) and no_hold and serving:
                            add('routing_eligible', 'eligible', at)
            except (ValueError, TypeError, OverflowError):
                pass  # Missing eligibility never erases independent process evidence.
            return DiagnosticCollection(AdapterResult(readings, ()), completed, log)
        except Exception as error:
            # Counter observations remain source claims when diagnostic metadata
            # is unsupported or identity unavailable; no stale proof is promoted.
            readings = dict(baseline.result.readings) if 'baseline' in locals() else {}
            readings.pop('model_state', None)
            reason = 'permission_denied' if isinstance(error, PermissionError) else 'unavailable'
            if 'baseline' not in locals() and not isinstance(error, OSError):
                reason = 'invalid_state'
            return DiagnosticCollection(AdapterResult(readings, (reason,) if not readings else ()),
                                        now, unknown('target_or_state_unverified', now))
