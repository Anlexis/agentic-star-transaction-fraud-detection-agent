"""AgentCore Platform v1.0"""

# FIN-C2-064 — transaction-event contract.
#
# Service layer: the declared shape of a caller's transaction event, the bounds
# every field must satisfy, and the screens a payload must clear before any
# domain node reads it. No routing and no credentials live here.
#
# The contract is a closed set. A field this module does not declare is DROPPED,
# not ignored: an ignored key stays in the payload, travels into agent state and
# is returned verbatim by the first node's result, where the framework's output
# check scans it. Dropping is what keeps an undeclared field from reaching that
# scan, and it is also what keeps a raw account number out of state even when a
# caller sends one under a name nobody anticipated.
#
# Numbers are validated, never rewritten. An earlier revision redacted anything
# that looked like an account number out of the raw payload text before parsing
# it, which rewrote ordinary transaction amounts (25000 is a five-digit run) and
# broke the JSON, so every downstream signal collapsed to its zero value and a
# large suspicious transaction scored lower than a small one. Validation reports
# a bad field; it does not edit the caller's data.

from __future__ import annotations

import json
import re
from typing import Any, Dict, Final, List, Mapping, Optional, Tuple

from framework.security.credential_detector import detect_credentials_in_value
from framework.security.pii_detector import detect_pii

# ── Size bounds ───────────────────────────────────────────────────────────────

MIN_EVENT_CHARS: Final[int] = 2
MAX_EVENT_CHARS: Final[int] = 8192

# Context-channel fields the adapter is allowed to forward. Everything else is
# dropped before invoke() is called.
CALLER_CONTEXT_FIELDS: Final[frozenset[str]] = frozenset({"channel"})

# ── Field contract ────────────────────────────────────────────────────────────

# Inert identifier alphabet for every caller string that survives into state or
# into the dispatched alert. Free text is not accepted anywhere in the contract.
_INERT_ID: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_COUNTRY: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]{2}$")
_CURRENCY: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")

# A contiguous or separator-grouped run of 13-19 digits is an account number
# shape. It is refused rather than masked: the caller must not send one, and a
# masked value would leave the alert claiming a reference it does not have.
_ACCOUNT_NUMBER: Final[re.Pattern[str]] = re.compile(r"(?<![0-9])(?:[0-9][ -]?){13,19}(?![0-9])")

# Chat-template control markers. This class is screened by the template itself
# because the framework's own screen scores `<<SYS>>` as no finding at all while
# blocking `<|im_start|>` and `[INST]` — a payload wrapped in the third form
# reaches the answer path untouched.
_CONTROL_MARKERS: Final[Tuple[re.Pattern[str], ...]] = (
    re.compile(r"<\|[^>\n]{0,64}\|>"),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
    re.compile(r"<</?SYS>>", re.IGNORECASE),
)

# Numeric bounds, per field: (minimum, maximum).
_NUMERIC_BOUNDS: Final[Dict[str, Tuple[float, float]]] = {
    "amount": (0.0, 1e12),
    "recent_txn_count": (0.0, 1e6),
}

# Every field the contract declares, with the validator that owns it.
_STRING_FIELDS: Final[Dict[str, re.Pattern[str]]] = {
    "txn_id": _INERT_ID,
    "device_id": _INERT_ID,
    "merchant_id": _INERT_ID,
    "txn_country": _COUNTRY,
    "home_country": _COUNTRY,
    "currency": _CURRENCY,
}
_BOOL_FIELDS: Final[Tuple[str, ...]] = ("device_known",)

DECLARED_FIELDS: Final[frozenset[str]] = frozenset(set(_STRING_FIELDS) | set(_BOOL_FIELDS) | set(_NUMERIC_BOUNDS))

# Closed set of refusal reasons. A reason names a location and a category —
# never the value that produced it, and never a matched substring.
REASON_NOT_JSON_OBJECT: Final[str] = "not_a_json_object"
REASON_EMPTY: Final[str] = "empty"
REASON_TOO_LONG: Final[str] = "too_long"
REASON_TOO_SHORT: Final[str] = "too_short"
REASON_NOT_A_STRING: Final[str] = "not_a_string"
REASON_WRONG_TYPE: Final[str] = "wrong_type"
REASON_MALFORMED: Final[str] = "malformed"
REASON_NOT_FINITE: Final[str] = "not_finite"
REASON_OUT_OF_RANGE: Final[str] = "out_of_range"
REASON_CONTROL_MARKERS: Final[str] = "control_markers_present"
REASON_ACCOUNT_NUMBER: Final[str] = "account_number_present"
REASON_CREDENTIAL_SHAPE: Final[str] = "credential_shaped_value"
REASON_PERSONAL_DATA: Final[str] = "personal_data_present"
REASON_NO_DECLARED_FIELDS: Final[str] = "no_declared_fields"


class EventContractError(Exception):
    """A caller payload failed the declared contract.

    Carries a field label and a reason drawn from the closed set above. Neither
    the offending value nor any substring of it is retained, so the message is
    safe to place in an error log and safe to return to the caller.
    """

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"{field}: {reason}")

    def as_message(self) -> str:
        return f"transaction event rejected — {self.field}: {self.reason}"


def _finite_in_range(value: Any, low: float, high: float) -> float:
    """Return *value* as a float, or raise for anything not finite and in range.

    ``bool`` is rejected before the numeric branch because it is an ``int`` in
    Python and ``True`` would otherwise be accepted as the amount 1.0. NaN and
    the infinities parse cleanly through ``float()`` and arrive intact through
    raw JSON, and every comparison against them is False — so a threshold test
    would pass silently. They are refused here instead.
    """
    if isinstance(value, bool):
        raise ValueError(REASON_WRONG_TYPE)
    if isinstance(value, str):
        try:
            number = float(value.strip())
        except (TypeError, ValueError):
            raise ValueError(REASON_MALFORMED) from None
    elif isinstance(value, (int, float)):
        number = float(value)
    else:
        raise ValueError(REASON_WRONG_TYPE)
    if number != number or number in (float("inf"), float("-inf")):
        raise ValueError(REASON_NOT_FINITE)
    if not (low <= number <= high):
        raise ValueError(REASON_OUT_OF_RANGE)
    return number


def _has_control_markers(text: str) -> bool:
    """True when *text* carries a chat-template control marker.

    Checked twice: on the text as received, which catches a marker whole, and on
    the text with angle-bracket markup removed, which re-assembles a marker that
    was spliced apart. Removing markup first only would delete the marker and
    forward the directive behind it as ordinary prose.
    """
    if any(pattern.search(text) for pattern in _CONTROL_MARKERS):
        return True
    stripped = re.sub(r"<[^<>]{0,64}>", "", text)
    return any(pattern.search(stripped) for pattern in _CONTROL_MARKERS)


def _screen_structure(node: Any, path: str) -> None:
    """Screen every key and every string leaf of a parsed payload.

    Keys are caller data too: a control marker used as a field name reaches the
    same places a value does. The walk runs after parsing, so an escaped payload
    is screened in its decoded form.
    """
    if isinstance(node, Mapping):
        for key, value in node.items():
            key_text = str(key)
            if _has_control_markers(key_text):
                raise EventContractError(f"{path}.<field name>", REASON_CONTROL_MARKERS)
            _screen_structure(value, f"{path}.{key_text}" if _INERT_ID.match(key_text) else f"{path}.<field>")
        return
    if isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            _screen_structure(item, f"{path}[{index}]")
        return
    if isinstance(node, str):
        if _has_control_markers(node):
            raise EventContractError(path, REASON_CONTROL_MARKERS)


def _screen_string_value(field: str, value: str) -> None:
    """Refuse a declared string field carrying data it must never carry."""
    if _ACCOUNT_NUMBER.search(value):
        raise EventContractError(field, REASON_ACCOUNT_NUMBER)
    if detect_credentials_in_value(value):
        raise EventContractError(field, REASON_CREDENTIAL_SHAPE)


def validate_event(raw: Any) -> Dict[str, Any]:
    """Validate a caller transaction event and return the accepted fields only.

    The return value contains nothing the contract does not declare, so it is
    safe to serialize into agent state and to hand to the domain pipeline.
    """
    if not isinstance(raw, str):
        raise EventContractError("input", REASON_NOT_A_STRING)
    text = raw.strip()
    if not text:
        raise EventContractError("input", REASON_EMPTY)
    if len(text) < MIN_EVENT_CHARS:
        raise EventContractError("input", REASON_TOO_SHORT)
    if len(text) > MAX_EVENT_CHARS:
        raise EventContractError("input", REASON_TOO_LONG)
    if _has_control_markers(text):
        raise EventContractError("input", REASON_CONTROL_MARKERS)

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        raise EventContractError("input", REASON_NOT_JSON_OBJECT) from None
    if not isinstance(parsed, dict):
        raise EventContractError("input", REASON_NOT_JSON_OBJECT)

    _screen_structure(parsed, "input")

    accepted: Dict[str, Any] = {}
    for field in sorted(parsed):
        if field not in DECLARED_FIELDS:
            continue  # dropped, not carried forward
        value = parsed[field]
        if field in _NUMERIC_BOUNDS:
            low, high = _NUMERIC_BOUNDS[field]
            try:
                accepted[field] = _finite_in_range(value, low, high)
            except ValueError as exc:
                raise EventContractError(field, str(exc)) from None
        elif field in _BOOL_FIELDS:
            if not isinstance(value, bool):
                raise EventContractError(field, REASON_WRONG_TYPE)
            accepted[field] = value
        else:
            pattern = _STRING_FIELDS[field]
            if not isinstance(value, str):
                raise EventContractError(field, REASON_WRONG_TYPE)
            if not pattern.match(value):
                raise EventContractError(field, REASON_MALFORMED)
            _screen_string_value(field, value)
            accepted[field] = value

    if not accepted:
        raise EventContractError("input", REASON_NO_DECLARED_FIELDS)
    return accepted


def canonical_event(accepted: Mapping[str, Any]) -> str:
    """Serialize accepted fields to the string the domain pipeline reads.

    The result is screened once more for personal-data shapes. The framework
    masks personal data in the input fields of every node it runs, so a value
    that trips that detector would be rewritten mid-pipeline and the payload
    would stop parsing. Refusing here converts that into a stated refusal.
    """
    text = json.dumps(dict(sorted(accepted.items())), ensure_ascii=False, sort_keys=True)
    if detect_pii(text):
        raise EventContractError("input", REASON_PERSONAL_DATA)
    return text


def validated_context(raw: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """Reduce a caller context mapping to the declared, inert fields."""
    if not raw:
        return {}
    reduced: Dict[str, str] = {}
    for key in sorted(raw, key=str):
        if key not in CALLER_CONTEXT_FIELDS:
            continue
        value = raw[key]
        if isinstance(value, str) and _INERT_ID.match(value):
            reduced[str(key)] = value
    return reduced


class Service:
    """Domain service for the transaction-event contract."""

    def declared_fields(self) -> List[str]:
        """Return the accepted field names, in a stable order."""
        return sorted(DECLARED_FIELDS)

    def validate(self, raw: Any) -> Dict[str, Any]:
        """Validate a caller payload and return the accepted fields."""
        return validate_event(raw)
