# The four domain steps: signals, score, severity, alert.
#
# Each step is driven with the state its predecessor actually produces, not with
# a hand-built mapping, so a step that reads a key nothing writes shows up here
# rather than in production.

import json

import pytest

from framework.schemas.agent_status import AgentStatus

from src.nodes.classify_severity_node import (
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    ClassifySeverityNode,
    band_for,
)
from src.nodes.compose_dispatch_alert_node import (
    FLAG_REASONS,
    NO_SIGNAL_REASON,
    SEVERITY_ACTION,
    ComposeDispatchAlertNode,
    masked_reference,
)
from src.nodes.extract_fraud_signals_node import (
    GEO_MISMATCH,
    HIGH_AMOUNT,
    NEW_DEVICE,
    VELOCITY_EXCEEDED,
    ExtractFraudSignalsNode,
)
from src.nodes.score_fraud_risk_node import ScoreFraudRiskNode
from src.schemas.state import from_json
from src.services.service import canonical_event, validate_event

ALL_SIGNALS = {
    "txn_id": "TXN-20260904-001",
    "amount": 25000,
    "recent_txn_count": 9,
    "txn_country": "US",
    "home_country": "JP",
    "device_id": "dev-77",
    "device_known": False,
}
NO_SIGNALS = {
    "txn_id": "TXN-20260904-002",
    "amount": 12,
    "recent_txn_count": 1,
    "txn_country": "JP",
    "home_country": "JP",
    "device_id": "dev-1",
    "device_known": True,
}


def _pipeline(event: dict) -> dict:
    """Run the four domain steps in order and return the accumulated state."""
    state: dict = {"validated_input": canonical_event(validate_event(json.dumps(event)))}
    state.update(ExtractFraudSignalsNode().execute(state))
    state.update(ScoreFraudRiskNode().execute(state))
    state.update(ClassifySeverityNode().execute(state))
    state.update(ComposeDispatchAlertNode().execute(state))
    return state


class TestSignalExtraction:
    def test_every_signal_is_raised(self):
        signals = from_json(_pipeline(ALL_SIGNALS)["fraud_signals"], {})
        assert set(signals["flags"]) == {
            VELOCITY_EXCEEDED,
            GEO_MISMATCH,
            NEW_DEVICE,
            HIGH_AMOUNT,
        }

    def test_no_signal_is_raised_on_a_clean_event(self):
        signals = from_json(_pipeline(NO_SIGNALS)["fraud_signals"], {})
        assert signals["flags"] == []

    def test_large_amount_raises_the_amount_signal(self):
        """A five-digit amount must be read as an amount.

        This is the case that used to be rewritten before parsing, which left
        every signal at its zero value: the larger the transaction, the lower
        the score it received.
        """
        signals = from_json(_pipeline(dict(NO_SIGNALS, amount=25000))["fraud_signals"], {})
        assert HIGH_AMOUNT in signals["flags"]
        assert signals["amount"]["value"] == 25000.0

    def test_amount_below_the_threshold_raises_nothing(self):
        signals = from_json(_pipeline(dict(NO_SIGNALS, amount=999))["fraud_signals"], {})
        assert HIGH_AMOUNT not in signals["flags"]

    def test_same_country_is_not_a_mismatch(self):
        signals = from_json(_pipeline(dict(ALL_SIGNALS, txn_country="JP"))["fraud_signals"], {})
        assert GEO_MISMATCH not in signals["flags"]

    def test_known_device_is_not_new(self):
        signals = from_json(_pipeline(dict(ALL_SIGNALS, device_known=True))["fraud_signals"], {})
        assert NEW_DEVICE not in signals["flags"]

    def test_signals_are_stored_as_a_json_string(self):
        assert isinstance(_pipeline(ALL_SIGNALS)["fraud_signals"], str)


class TestRiskScoring:
    def test_all_signals_score_one(self):
        assert _pipeline(ALL_SIGNALS)["fraud_score"] == 1.0

    def test_no_signals_score_zero(self):
        assert _pipeline(NO_SIGNALS)["fraud_score"] == 0.0

    def test_score_stays_within_bounds(self):
        for event in (ALL_SIGNALS, NO_SIGNALS, dict(NO_SIGNALS, recent_txn_count=99)):
            assert 0.0 <= _pipeline(event)["fraud_score"] <= 1.0

    def test_a_single_signal_scores_its_declared_weight(self):
        state = _pipeline(dict(NO_SIGNALS, recent_txn_count=99))
        assert state["fraud_score"] == 0.30

    def test_missing_signals_field_scores_zero(self):
        assert ScoreFraudRiskNode().execute({})["fraud_score"] == 0.0

    def test_corrupt_signals_field_scores_zero(self):
        assert ScoreFraudRiskNode().execute({"fraud_signals": "not json"})["fraud_score"] == 0.0


class TestSeverityClassification:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (1.0, CRITICAL),
            (0.85, CRITICAL),
            (0.84, HIGH),
            (0.60, HIGH),
            (0.59, MEDIUM),
            (0.30, MEDIUM),
            (0.29, LOW),
            (0.0, LOW),
        ],
    )
    def test_bands_use_inclusive_lower_bounds(self, score, expected):
        assert ClassifySeverityNode().execute({"fraud_score": score})["severity"] == expected

    @pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_score_falls_to_the_lowest_band(self, score):
        """Every comparison against a non-finite score is False, so an
        unguarded banding would return the lowest band by accident rather than
        by decision. It is made a decision here."""
        assert ClassifySeverityNode().execute({"fraud_score": score})["severity"] == LOW

    def test_unreadable_score_falls_to_the_lowest_band(self):
        assert ClassifySeverityNode().execute({"fraud_score": "high"})["severity"] == LOW

    def test_band_helper_matches_the_node(self):
        thresholds = {CRITICAL: 0.85, HIGH: 0.60, MEDIUM: 0.30}
        assert band_for(0.7, thresholds) == HIGH


class TestAlertComposition:
    def test_alert_carries_every_declared_key(self):
        alert = from_json(_pipeline(ALL_SIGNALS)["alert_payload"], {})
        assert set(alert) == {
            "alert_id",
            "txn_ref_masked",
            "severity",
            "fraud_score",
            "reasons",
            "recommended_action",
            "channel",
            "generated_at",
        }

    def test_reference_is_a_digest_not_the_caller_identifier(self):
        alert = from_json(_pipeline(ALL_SIGNALS)["alert_payload"], {})
        assert ALL_SIGNALS["txn_id"] not in json.dumps(alert)
        assert alert["alert_id"].startswith("TXN-")
        assert len(alert["alert_id"]) == len("TXN-") + 12

    def test_two_transactions_with_the_same_signals_get_different_references(self):
        """The reference used to be a digest of the severity and the flags
        alone, so unrelated transactions shared one alert id and an analyst
        could not tell which transaction an alert was about."""
        first = from_json(_pipeline(ALL_SIGNALS)["alert_payload"], {})
        second = from_json(_pipeline(dict(ALL_SIGNALS, txn_id="TXN-20260904-999"))["alert_payload"], {})
        assert first["severity"] == second["severity"]
        assert first["alert_id"] != second["alert_id"]

    def test_reference_is_stable_for_the_same_transaction(self):
        assert masked_reference("t1", CRITICAL, ["a"]) == masked_reference("t1", CRITICAL, ["a"])

    def test_reasons_come_from_the_fixed_table(self):
        alert = from_json(_pipeline(ALL_SIGNALS)["alert_payload"], {})
        assert set(alert["reasons"]) <= set(FLAG_REASONS.values()) | {NO_SIGNAL_REASON}

    def test_clean_event_states_that_no_signal_fired(self):
        alert = from_json(_pipeline(NO_SIGNALS)["alert_payload"], {})
        assert alert["reasons"] == [NO_SIGNAL_REASON]

    def test_action_matches_the_severity(self):
        alert = from_json(_pipeline(ALL_SIGNALS)["alert_payload"], {})
        assert alert["recommended_action"] == SEVERITY_ACTION[alert["severity"]]

    def test_channel_defaults_when_none_was_supplied(self):
        alert = from_json(_pipeline(ALL_SIGNALS)["alert_payload"], {})
        assert alert["channel"] == "unknown"

    def test_terminal_step_reports_success(self):
        assert _pipeline(ALL_SIGNALS)["status"] == AgentStatus.SUCCESS.value

    def test_alert_renders_no_monetary_value(self):
        """The alert reports a bounded risk score and a severity label; it does
        not restate the transaction amount, so there is no monetary figure in it
        for a rounding rule to govern."""
        alert = from_json(_pipeline(dict(ALL_SIGNALS, amount=123456))["alert_payload"], {})
        assert "123456" not in json.dumps(alert)
        assert 0.0 <= alert["fraud_score"] <= 1.0
