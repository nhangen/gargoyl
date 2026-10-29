"""Bounded in-memory parsers for pinned Darkbloom text formats; no execution.

Producer: darkbloomdev/darkbloom a6f7f483ab88806c633e37e00339c13e37ab62f4,
provider/src/main.rs cmd_status and cmd_doctor. Only fixed states leave parsing.
"""
import re
from dataclasses import dataclass

from gargoyl.telemetry import PolicyError, timestamp

SOURCE_KINDS = frozenset({"darkbloom_status_text_v1", "darkbloom_doctor_text_v1"})
MAX_SOURCE_BYTES = 65536
_CHECK_LABELS = (
    "1. Hardware detection........... ",
    "2. System Integrity Protection.. ",
    "3. Secure Enclave.............. ",
    "4. MDM enrollment.............. ",
    "5. Inference runtime........... ",
    "6. Downloaded models........... ",
    "7. Text E2E key................ ",
    "8. Coordinator connectivity.... ",
)


@dataclass(frozen=True)
class AdapterResult:
    readings: dict[str, dict]
    errors: tuple[str, ...]


def execution_failure(code):
    """Map an acquisition failure without retaining exception/output text."""
    if type(code) is not str or code not in {"timeout", "unavailable", "permission_denied"}:
        raise PolicyError("invalid source failure code")
    return AdapterResult({}, (code,))


def _status(lines):
    candidates = [line.strip() for line in lines if line.strip().startswith("Status")]
    if len(candidates) != 1:
        return None
    if re.fullmatch(r"Status: +● Running(?: — serving [^\r\n]+)?", candidates[0]):
        return "running"
    if re.fullmatch(r"Status: +○ Stopped", candidates[0]):
        return "stopped"
    return None


def _doctor(lines):
    # Exact header/check sequence prevents advice, duplicates or truncation from
    # being mistaken for completed checks. Ignore prose only after the summary.
    nonempty = [line for line in lines if line]
    if not nonempty or nonempty[0] != "Darkbloom Doctor — System Diagnostics":
        return None
    if len(nonempty) < 10:
        return None
    passed = 0
    success_patterns = (
        r"✓ .+ \([0-9]+ GB, [0-9]+ GPU cores\)",
        r"✓ Enabled", r"✓ Available", r"✓ Enrolled",
        r"✓ (?:vllm-mlx|mlx-lm) [0-9][A-Za-z0-9.+-]*",
        r"✓ [1-9][0-9]* model\(s\) found", r"✓ Secure Enclave-backed",
        r"✓ Online \((?:[0-9]+|null) providers\)",
    )
    failure_patterns = (
        r"✗ Failed: .+", r"✗ DISABLED — provider cannot serve safely",
        r"✗ eigeninference-enclave not found", r"✗ Not enrolled",
        r"✗ Not installed", r"✗ No models downloaded", r"✗ Unavailable",
        r"✗ (?:HTTP [1-5][0-9]{2}(?: [A-Za-z ]+)?|Unreachable: .+)",
    )
    for index, prefix in enumerate(_CHECK_LABELS):
        line = nonempty[index + 1]
        if not line.startswith(prefix):
            return None
        value = line[len(prefix):]
        if re.fullmatch(success_patterns[index], value):
            passed += 1
        elif re.fullmatch(failure_patterns[index], value):
            pass
        elif index in (2, 3) and value == "- Not applicable (non-macOS)":
            passed += 1
        else:
            return None
    if nonempty[9] != f"Result: {passed}/8 checks passed":
        return None
    # A second check/report in the footer is ambiguous, not evidence of health.
    if any(line.lstrip().startswith(("Result:", "Darkbloom Doctor"))
           or re.match(r"[0-9]+\.", line)
           for line in nonempty[10:]):
        return None
    footer = nonempty[10:]
    if passed == 8 and footer != ["All good! Start serving with: darkbloom serve"]:
        return None
    if passed != 8 and (not footer or footer[0] != "Issues to fix:"):
        return None
    return "passed" if passed == 8 else "failed"


def parse_observations(source_kind, payload, *, observed_at, ttl=60):
    """Return only allowlisted observations; malformed source bytes fail closed."""
    if type(source_kind) is not str or source_kind not in SOURCE_KINDS:
        raise PolicyError("invalid source kind")
    timestamp(observed_at)
    if type(ttl) is not int or not 1 <= ttl <= 86400:
        raise PolicyError("invalid source freshness")
    invalid = AdapterResult({}, ("invalid_state",))
    if type(payload) is not bytes or len(payload) > MAX_SOURCE_BYTES:
        return invalid
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        return invalid
    # No terminal escapes, NUL, C1 controls or Unicode line-separator ambiguity.
    if any((ord(c) < 32 and c not in "\n\r") or 127 <= ord(c) <= 159
           or c in "\u2028\u2029" for c in text):
        return invalid
    lines = text.replace("\r\n", "\n").split("\n")
    if any("\r" in line for line in lines):
        return invalid
    if source_kind == "darkbloom_status_text_v1":
        value, metric, source = _status(lines), "daemon_state", "daemon"
    else:
        value, metric, source = _doctor(lines), "doctor_state", "doctor"
    if value is None:
        return invalid
    return AdapterResult({metric: dict(value=value, source=source, timestamp=observed_at,
                         freshness_seconds=ttl, state="observed", sensitivity="safe")}, ())
