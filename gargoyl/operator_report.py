"""Bounded, read-only operator reporting; no authorization is minted here."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gargoyl.dashboard import render_dashboard
from gargoyl.repair_contract import RepairAuditEntry
from gargoyl.repair_view import render_audit_entry
from gargoyl.telemetry import encode_snapshot, host_id, timestamp, validate_snapshot

if TYPE_CHECKING:
    from gargoyl.repair_operator import OperatorReadAuthorization

MAX_INPUT_BYTES = 1024 * 1024
UNAVAILABLE = ('<!doctype html><html><head><meta charset="utf-8">'
               '<title>Operator report unavailable</title></head><body>'
               '<h1>Operator report unavailable</h1><p>Evidence and audit results unavailable. '
               'No health, successful outcome or retry permission is established.</p></body></html>')


def _identities(values, limit):
    if type(values) not in (list, tuple) or len(values) > limit:
        raise ValueError('invalid report inventory')
    result = tuple(host_id(value) for value in values)
    if len(set(result)) != len(result):
        raise ValueError('invalid report inventory')
    return result


def _body(page):
    # These are complete documents from our fixed, escaping renderers, never
    # user-supplied HTML. Reuse their validated projections and evidence wording.
    return page.split('<body>', 1)[1].rsplit('</body>', 1)[0]


def render_operator_report(*, authorization: OperatorReadAuthorization,
                           evidence_reader, audit_reader, expected_hosts,
                           audit_ids, now) -> str:
    """Authenticate twice and discard the entire report on any failed read.

    Readers must return bounded detached snapshots and validated audit wrappers.
    A current audit grant permits reading that host's historical preflight too;
    it does not confer access to its current evidence stream.
    """
    try:
        # Import the shared verifier, never a replacement or structural auth stub.
        from gargoyl.repair_operator import OperatorReadAuthorization

        if type(authorization) is not OperatorReadAuthorization:
            raise ValueError('invalid report authorization')
        scope = authorization.read_scope()
        timestamp(now)
        inventory = _identities(expected_hosts, 16)
        identifiers = _identities(audit_ids, 32)
        snapshots = evidence_reader.snapshots(now=now)
        if type(snapshots) not in (list, tuple) or len(snapshots) > 256:
            raise ValueError('invalid report evidence')
        used = 0
        visible = []
        for snapshot in snapshots:
            checked = validate_snapshot(snapshot)
            used += len(encode_snapshot(checked))
            if used > MAX_INPUT_BYTES:
                raise ValueError('report input limit exceeded')
            if checked['host_id'] in scope.evidence_hosts:
                visible.append(checked)
        audits = []
        for identifier in identifiers:
            entry = audit_reader.lookup(identifier)
            if entry is not None:
                if type(entry) is not RepairAuditEntry:
                    raise ValueError('invalid report audit')
                checked = RepairAuditEntry(entry.payload)
                value = checked.as_dict()
                if value['confirmation']['click_id'] != identifier:
                    raise ValueError('invalid report audit binding')
                entry = checked if value['plan']['target_host'] in scope.audit_hosts else None
                # Denied and missing lookups consume the same report budget.
                # Each inspected wrapper still has the shared 64 KiB cap, and
                # there are at most 32 lookups, including denied ones.
                if entry is not None:
                    used += len(checked.payload)
                    if used > MAX_INPUT_BYTES:
                        raise ValueError('report input limit exceeded')
            audits.append(_body(render_audit_entry(entry)))
        evidence = _body(render_dashboard(
            visible, [identity for identity in inventory if identity in scope.evidence_hosts], now=now))
        page = ('<!doctype html><html><head><meta charset="utf-8">'
                '<title>Operator report</title></head><body><h1>Operator report</h1>'
                '<p>Read-only evidence and historical audit report. This report grants no '
                'permission to execute or retry an operation. Regenerate to refresh; '
                'this document does not schedule browser refreshes.</p>'
                + evidence + ''.join(audits) + '</body></html>')
        if authorization.read_scope() != scope:
            raise ValueError('report authorization changed')
        return page
    except Exception:
        # Never disclose exceptions, denied host identifiers, or partial results.
        return UNAVAILABLE
