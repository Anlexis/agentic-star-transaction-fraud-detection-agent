# The declared runtime parameters are the ones in force.
#
# A node that reads a `config` argument on execute() never receives one — the
# node runner calls execute(state) and nothing else — so every declared value
# used to be dead and the in-code fallback was always what ran. These tests pin
# the live path: config/config.yaml is read, and a change to it changes what the
# pipeline does.

import json
from pathlib import Path

import pytest
import yaml

from src.nodes.classify_severity_node import _declared_thresholds
from src.nodes.extract_fraud_signals_node import HIGH_AMOUNT, ExtractFraudSignalsNode
from src.nodes.score_fraud_risk_node import _declared_weights
from src.runtime_config import (
    domain_config,
    load_config,
    reset_runtime_config,
    runtime_config,
    set_runtime_config,
)
from src.schemas.state import from_json

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


@pytest.fixture(autouse=True)
def _restore_declared_config():
    reset_runtime_config()
    yield
    reset_runtime_config()


def _declared() -> dict:
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))


class TestDeclaredFileIsRead:
    def test_config_file_ships(self):
        assert CONFIG_PATH.exists()

    def test_runtime_values_come_from_the_file(self):
        declared = _declared()
        assert runtime_config()["max_retry"] == declared["max_retry"]
        assert runtime_config()["timeout_s"] == declared["timeout_s"]

    def test_domain_block_comes_from_the_file(self):
        declared = _declared()["fin_c2_064"]
        assert domain_config()["velocity_window_max"] == declared["velocity_window_max"]
        assert domain_config()["high_amount_threshold"] == declared["high_amount_threshold"]

    def test_declared_weights_come_from_the_file(self):
        assert _declared_weights() == _declared()["fin_c2_064"]["signal_weights"]

    def test_declared_bands_come_from_the_file(self):
        assert _declared_thresholds() == _declared()["fin_c2_064"]["severity_thresholds"]

    def test_no_key_without_a_reader(self):
        """Every key in the domain block is read by something. A declaration
        nobody reads is a claim the agent does not honour."""
        assert set(_declared()["fin_c2_064"]) == {
            "velocity_window_max",
            "high_amount_threshold",
            "signal_weights",
            "severity_thresholds",
        }


class TestDeclaredValueChangesBehaviour:
    def test_amount_threshold_governs_the_signal(self):
        event = json.dumps({"amount": 100.0})

        set_runtime_config({"fin_c2_064": {"high_amount_threshold": 1000.0}})
        signals = from_json(ExtractFraudSignalsNode().execute({"validated_input": event})["fraud_signals"], {})
        assert HIGH_AMOUNT not in signals["flags"]

        set_runtime_config({"fin_c2_064": {"high_amount_threshold": 50.0}})
        signals = from_json(ExtractFraudSignalsNode().execute({"validated_input": event})["fraud_signals"], {})
        assert HIGH_AMOUNT in signals["flags"]
        assert signals["amount"]["high_amount_threshold"] == 50.0


class TestUnusableDeclarations:
    @pytest.mark.parametrize("value", [float("nan"), float("inf"), "soon", True, None])
    def test_unusable_threshold_falls_back(self, value):
        """A non-finite threshold makes every comparison against it False, so a
        high-value transaction would raise no signal at all."""
        set_runtime_config({"fin_c2_064": {"high_amount_threshold": value}})
        signals = from_json(
            ExtractFraudSignalsNode().execute({"validated_input": json.dumps({"amount": 5000.0})})["fraud_signals"],
            {},
        )
        assert signals["amount"]["high_amount_threshold"] == 1000.0
        assert HIGH_AMOUNT in signals["flags"]

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), 5.0, -1.0, "x"])
    def test_unusable_weight_falls_back(self, value):
        set_runtime_config({"fin_c2_064": {"signal_weights": {"geo_mismatch": value}}})
        assert _declared_weights()["geo_mismatch"] == 0.30

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), 2.0, "x"])
    def test_unusable_band_falls_back(self, value):
        set_runtime_config({"fin_c2_064": {"severity_thresholds": {"CRITICAL": value}}})
        assert _declared_thresholds()["CRITICAL"] == 0.85

    def test_unknown_signal_weight_is_ignored(self):
        set_runtime_config({"fin_c2_064": {"signal_weights": {"invented_signal": 0.9}}})
        assert "invented_signal" not in _declared_weights()

    def test_missing_file_degrades_to_defaults(self, tmp_path):
        assert load_config(tmp_path / "absent.yaml") == {}

    def test_unreadable_file_degrades_to_defaults(self, tmp_path):
        broken = tmp_path / "config.yaml"
        broken.write_text("max_retry: [unclosed", encoding="utf-8")
        assert load_config(broken) == {}

    def test_non_mapping_file_degrades_to_defaults(self, tmp_path):
        listy = tmp_path / "config.yaml"
        listy.write_text("- one\n- two\n", encoding="utf-8")
        assert load_config(listy) == {}
