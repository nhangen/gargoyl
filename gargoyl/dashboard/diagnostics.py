"""Diagnostic projection of validated normalized evidence, never repair policy."""
from gargoyl.telemetry import timestamp


def coordinator_diagnostics(history):
    """Retained current error observations are warnings, not distinct event counts.

    Caller supplies build_dashboard's validated, read-time-aged error history.
    Repeated polls of one source timestamp count once. Conflicting reports and
    a newer future-collected copy cannot establish an observation at that time.
    No error reports (or a reported `none`) prove protocol compatibility.
    """
    grouped = {}
    for item in history:
        if item['source'] == 'coordinator':
            grouped.setdefault(timestamp(item['timestamp']), []).append(item)
    observations = []
    for at, items in grouped.items():
        signatures = {(item['value'], item['reported_state'], item['freshness_seconds'])
                      for item in items}
        if len(signatures) != 1:
            continue
        chosen = max(items, key=lambda item: timestamp(item['collected_at']))
        if chosen['state'] == 'observed' and chosen['value'] != 'none':
            observations.append((at.isoformat().replace('+00:00', 'Z'), chosen['value']))
    observations.sort(key=lambda item: timestamp(item[0]))
    return {'state': 'warning' if observations else 'unknown',
            'observation_times': [at for at, _ in observations],
            'codes': sorted({code for _, code in observations}),
            'recurrence': 'repeated_observations' if len(observations) > 1 else 'unknown',
            'protocol_confidence': 'unknown', 'root_cause': 'unknown'}
