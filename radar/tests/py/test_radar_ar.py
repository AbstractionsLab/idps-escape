#!/usr/bin/env python3
"""
Unit tests for RADAR Active Response script (radar_ar.py)
Tests the RiskEngine class and its risk calculation logic.
"""

import json

import pytest
import importlib.util
import importlib.machinery
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock


def load_radar_ar_module():
    """Load radar_ar.py as a module for testing."""
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scenarios" / "active_responses" / "radar_ar.py"
    assert script_path.exists(), f"Script not found at: {script_path}"

    loader = importlib.machinery.SourceFileLoader("radar_ar_under_test", str(script_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def radar_ar():
    """Fixture to load the radar_ar module."""
    return load_radar_ar_module()


@pytest.fixture
def mock_logger(radar_ar):
    """Create a mock logger for testing."""
    logger = Mock(spec=radar_ar.Logger)
    logger.log = Mock()
    return logger


@pytest.fixture
def risk_engine(radar_ar, mock_logger):
    """Create a RiskEngine instance with mock logger."""
    return radar_ar.RiskEngine(mock_logger)


class TestRiskEngine:
    """Test suite for RiskEngine class."""

    def test_signature_likelihood_scalar(self, risk_engine):
        """Test _signature_likelihood with scalar value."""
        cfg = {"signature_likelihood": 0.75}
        alert = {"rule": {"id": "100900"}}
        
        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.75

    def test_signature_likelihood_list_match(self, risk_engine):
        """Test _signature_likelihood with list config and matching rule."""
        cfg = {
            "signature_likelihood": [
                {"rule_id": ["100900", "100901"], "weight": 0.8},
                {"rule_id": ["100020", "100021"], "weight": 0.5},
            ]
        }
        alert = {"rule": {"id": "100900"}}
        
        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.8

    def test_signature_likelihood_list_no_match(self, risk_engine):
        """Test _signature_likelihood with list config but no matching rule."""
        cfg = {
            "signature_likelihood": [
                {"rule_id": ["100900", "100901"], "weight": 0.8},
            ]
        }
        alert = {"rule": {"id": "999999"}}
        
        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.0

    def test_signature_likelihood_single_rule_id(self, risk_engine):
        """Test _signature_likelihood with single rule_id (not a list)."""
        cfg = {
            "signature_likelihood": [
                {"rule_id": "100900", "weight": 0.6},
            ]
        }
        alert = {"rule": {"id": "100900"}}
        
        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.6

    def test_signature_likelihood_missing_rule_id(self, risk_engine):
        """Test _signature_likelihood when alert has no rule id with scalar config."""
        cfg = {"signature_likelihood": 0.75}
        alert = {}
        
        # With scalar config, likelihood is returned regardless of rule presence
        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.75
    
    def test_signature_likelihood_list_missing_rule_id(self, risk_engine):
        """Test _signature_likelihood when alert has no rule id with list config."""
        cfg = {
            "signature_likelihood": [
                {"rule_id": ["100900", "100901"], "weight": 0.8},
            ]
        }
        alert = {}
        
        # With list config and missing rule, should return 0.0
        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.0

    def test_signature_likelihood_rule_group_match(self, risk_engine):
        """Test _signature_likelihood with list config and matching rule_group."""
        cfg = {
            "signature_likelihood": [
                {"rule_group": "vulnerability-detector", "weight": 0.5},
            ]
        }
        alert = {"rule": {"id": "23502", "groups": ["vulnerability-detector"]}}

        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.5

    def test_signature_likelihood_rule_id_before_rule_group(self, risk_engine):
        """Test _signature_likelihood picks a specific rule_id entry over a later, more general rule_group entry."""
        cfg = {
            "signature_likelihood": [
                {"rule_id": "23506", "weight": 0.9},
                {"rule_group": "vulnerability-detector", "weight": 0.5},
            ]
        }
        alert = {"rule": {"id": "23506", "groups": ["vulnerability-detector"]}}

        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.9

    def test_signature_likelihood_catch_all_default(self, risk_engine):
        """Test _signature_likelihood falls back to a trailing entry with neither rule_id nor rule_group."""
        cfg = {
            "signature_likelihood": [
                {"rule_id": "23506", "weight": 0.9},
                {"rule_group": "vulnerability-detector", "weight": 0.5},
                {"weight": 0.3},
            ]
        }
        alert = {"rule": {"id": "999999", "groups": ["unrelated_group"]}}

        likelihood = risk_engine._signature_likelihood(cfg, alert)
        assert likelihood == 0.3

    def test_compute_signature_only(self, risk_engine, radar_ar):
        """Test compute with signature detection only (no AD)."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 0.8,
                "w_cti": 0.2,
                "signature_likelihood": 0.8,
                "signature_impact": 0.6,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "100900"}}
        }
        
        result = risk_engine.compute(scenario, 0.0, None, None)
        
        # S = 0.8 * 0.6 = 0.48
        # R = 0.0 * 0 + 0.8 * 0.48 + 0.2 * 0 = 0.384
        assert result["risk_score"] == pytest.approx(0.384, abs=0.001)
        assert result["tier"] == 2  # 0.33 <= 0.384 < 0.66
        assert result["components"]["signature_risk_S"] == pytest.approx(0.48, abs=0.001)
        assert result["components"]["anomaly_component"] == 0.0

    def test_compute_ad_only(self, risk_engine):
        """Test compute with anomaly detection only (no signature)."""
        scenario = {
            "name": "test_scenario",
            "detection": "ad",
            "config": {
                "w_ad": 0.9,
                "w_sig": 0.0,
                "w_cti": 0.1,
                "signature_likelihood": 0.0,
                "signature_impact": 0.0,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "100309"}}
        }
        ad_grade = 0.62
        ad_conf = 0.74
        
        result = risk_engine.compute(scenario, 0.0, ad_grade, ad_conf)
        
        # A = 0.62 * 0.74 = 0.4588
        # R = 0.9 * 0.4588 + 0.0 * 0 + 0.1 * 0 = 0.41292
        assert result["risk_score"] == pytest.approx(0.41292, abs=0.001)
        assert result["tier"] == 2
        assert result["components"]["anomaly_intensity_A"] == pytest.approx(0.4588, abs=0.001)
        assert result["components"]["signature_component"] == 0.0

    def test_compute_hybrid_detection(self, risk_engine):
        """Test compute with both AD and signature components (hybrid)."""
        scenario = {
            "name": "test_scenario",
            "detection": "hybrid",
            "config": {
                "w_ad": 0.3,
                "w_sig": 0.4,
                "w_cti": 0.3,
                "signature_likelihood": 0.5,
                "signature_impact": 0.7,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "210012"}}
        }
        ad_grade = 0.60
        ad_conf = 0.70
        
        result = risk_engine.compute(scenario, 0.8, ad_grade, ad_conf)
        
        # A = 0.60 * 0.70 = 0.42
        # S = 0.5 * 0.7 = 0.35
        # T = 0.8
        # R = 0.3 * 0.42 + 0.4 * 0.35 + 0.3 * 0.8
        # R = 0.126 + 0.14 + 0.24 = 0.506
        assert result["risk_score"] == pytest.approx(0.506, abs=0.001)
        assert result["tier"] == 2
        assert result["components"]["anomaly_component"] == pytest.approx(0.126, abs=0.001)
        assert result["components"]["signature_component"] == pytest.approx(0.14, abs=0.001)
        assert result["components"]["cti_component"] == pytest.approx(0.24, abs=0.001)

    def test_compute_spec_example(self, risk_engine):
        """Test compute with exact example from radar-risk-math.md spec."""
        scenario = {
            "name": "test_scenario",
            "detection": "hybrid",
            "config": {
                "w_ad": 0.4,
                "w_sig": 0.4,
                "w_cti": 0.2,
                "signature_likelihood": 0.4,
                "signature_impact": 0.9,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        ad_grade = 0.62
        ad_conf = 0.74
        
        result = risk_engine.compute(scenario, 0.76, ad_grade, ad_conf)
        
        # From spec:
        # A = 0.62 * 0.74 = 0.4588
        # S = 0.4 * 0.9 = 0.36
        # T = 0.76 (pre-computed by DECIPHER analyze endpoint)
        # R = 0.4*0.4588 + 0.4*0.36 + 0.2*0.76 = 0.4795
        assert result["risk_score"] == pytest.approx(0.4795, abs=0.001)
        assert result["tier"] == 2  # Medium risk
        assert result["components"]["anomaly_intensity_A"] == pytest.approx(0.4588, abs=0.001)
        assert result["components"]["signature_risk_S"] == pytest.approx(0.36, abs=0.001)
        assert result["components"]["cti_score_T"] == pytest.approx(0.76, abs=0.001)

    def test_compute_tier_1_low_risk(self, risk_engine):
        """Test tier assignment for low risk (tier 1)."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 1.0,
                "w_cti": 0.0,
                "signature_likelihood": 0.2,
                "signature_impact": 0.5,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        
        result = risk_engine.compute(scenario, 0.0, None, None)
        
        # S = 0.2 * 0.5 = 0.1
        # R = 1.0 * 0.1 = 0.1 < 0.33
        assert result["risk_score"] == 0.1
        assert result["tier"] == 1

    def test_compute_tier_0_below_min(self, risk_engine):
        """Test tier 0 when risk score is below tier1_min."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 1.0,
                "w_cti": 0.0,
                "signature_likelihood": 0.05,
                "signature_impact": 0.1,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.1, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }

        result = risk_engine.compute(scenario, 0.0, None, None)

        # R = 0.05 * 0.1 = 0.005 < tier1_min=0.1
        assert result["risk_score"] == pytest.approx(0.005, abs=0.001)
        assert result["tier"] == 0

    def test_compute_tier_boundary_at_tier1_min(self, risk_engine):
        """Test that R == tier1_min is classified as tier 1, not tier 0."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 1.0,
                "w_cti": 0.0,
                "signature_likelihood": 1.0,
                "signature_impact": 0.1,
                "risk_threshold": 0.0,
                "tiers": {"tier1_min": 0.1, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }

        result = risk_engine.compute(scenario, 0.0, None, None)

        # R = 1.0 * 0.1 = 0.1 == tier1_min; boundary is exclusive (< t1_min → tier 0)
        assert result["risk_score"] == pytest.approx(0.1, abs=0.001)
        assert result["tier"] == 1

    def test_compute_tier_boundary_at_tier1_max(self, risk_engine):
        """Test that R == tier1_max is classified as tier 2, not tier 1."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 1.0,
                "w_cti": 0.0,
                "signature_likelihood": 1.0,
                "signature_impact": 0.33,
                "risk_threshold": 0.0,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }

        result = risk_engine.compute(scenario, 0.0, None, None)

        # R = 0.33 == tier1_max; boundary is exclusive (< t1_max → tier 1)
        assert result["risk_score"] == pytest.approx(0.33, abs=0.001)
        assert result["tier"] == 2

    def test_compute_tier_boundary_at_tier2_max(self, risk_engine):
        """Test that R == tier2_max is classified as tier 3, not tier 2."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 1.0,
                "w_cti": 0.0,
                "signature_likelihood": 1.0,
                "signature_impact": 0.66,
                "risk_threshold": 0.0,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }

        result = risk_engine.compute(scenario, 0.0, None, None)

        # R = 0.66 == tier2_max; boundary is exclusive (< t2_max → tier 2)
        assert result["risk_score"] == pytest.approx(0.66, abs=0.001)
        assert result["tier"] == 3

    def test_compute_tier_0_unreachable_with_default_tier1_min(self, risk_engine):
        """Test that tier 0 is unreachable when tier1_min=0.0 (default)."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.0,
                "w_sig": 1.0,
                "w_cti": 0.0,
                "signature_likelihood": 0.0,
                "signature_impact": 0.0,
                "risk_threshold": 0.0,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }

        result = risk_engine.compute(scenario, 0.0, None, None)

        # R = 0.0; with tier1_min=0.0, condition is R < 0.0 which is never true
        assert result["risk_score"] == 0.0
        assert result["tier"] == 1

    def test_compute_tier_3_high_risk(self, risk_engine):
        """Test tier assignment for high risk (tier 3)."""
        scenario = {
            "name": "test_scenario",
            "detection": "ad",
            "config": {
                "w_ad": 0.9,
                "w_sig": 0.0,
                "w_cti": 0.1,
                "signature_likelihood": 0.0,
                "signature_impact": 0.0,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        ad_grade = 0.9
        ad_conf = 0.9
        
        result = risk_engine.compute(scenario, 1.0, ad_grade, ad_conf)
        
        # A = 0.9 * 0.9 = 0.81
        # T = 1.0
        # R = 0.9 * 0.81 + 0.1 * 1.0 = 0.729 + 0.1 = 0.829 >= 0.66
        assert result["risk_score"] == pytest.approx(0.829, abs=0.001)
        assert result["tier"] == 3

    def test_compute_clamping_above_1(self, risk_engine):
        """Test that risk score is clamped to [0,1] range (upper bound)."""
        scenario = {
            "name": "test_scenario",
            "detection": "signature",
            "config": {
                "w_ad": 0.5,
                "w_sig": 0.5,
                "w_cti": 0.5,  # Intentionally > 1.0 to test clamping
                "signature_likelihood": 1.0,
                "signature_impact": 1.0,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        
        result = risk_engine.compute(scenario, 1.0, None, None)
        
        # Without clamping: R = 0.5 * 1.0 + 0.5 * 1.0 = 1.5
        # With clamping: R = 1.0
        assert result["risk_score"] <= 1.0

    def test_compute_components_detail(self, risk_engine):
        """Test that components dict contains all expected fields."""
        scenario = {
            "name": "test_scenario",
            "detection": "hybrid",
            "config": {
                "w_ad": 0.3,
                "w_sig": 0.4,
                "w_cti": 0.3,
                "signature_likelihood": 0.5,
                "signature_impact": 0.7,
                "risk_threshold": 0.51,
                "tiers": {"tier1_min": 0.0, "tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        ad_grade = 0.6
        ad_conf = 0.7
        
        result = risk_engine.compute(scenario, 0.5, ad_grade, ad_conf)
        
        # Check all expected component fields exist
        assert "anomaly_component" in result["components"]
        assert "anomaly_intensity_A" in result["components"]
        assert "anomaly_grade" in result["components"]
        assert "anomaly_confidence" in result["components"]
        assert "signature_component" in result["components"]
        assert "signature_risk_S" in result["components"]
        assert "signature_likelihood" in result["components"]
        assert "signature_impact" in result["components"]
        assert "cti_component" in result["components"]
        assert "cti_score_T" in result["components"]
        assert "risk_score" in result["components"]
        
        # Verify values are rounded to 6 decimals
        assert result["components"]["anomaly_grade"] == 0.6
        assert result["components"]["anomaly_confidence"] == 0.7


class TestHelperFunctions:
    """Test suite for helper functions."""

    def test_to_float(self, radar_ar):
        """Test _to_float helper function."""
        assert radar_ar._to_float(0.5, 0.0) == 0.5
        assert radar_ar._to_float(5, 0.0) == 5.0
        assert radar_ar._to_float("0.75", 0.0) == 0.75
        assert radar_ar._to_float("invalid", 0.0) == 0.0
        assert radar_ar._to_float(None, 1.0) == 1.0

    def test_parse_bool(self, radar_ar):
        """Test _parse_bool helper function."""
        assert radar_ar._parse_bool("true") is True
        assert radar_ar._parse_bool("1") is True
        assert radar_ar._parse_bool("yes") is True
        assert radar_ar._parse_bool("on") is True
        assert radar_ar._parse_bool("false") is False
        assert radar_ar._parse_bool("0") is False
        assert radar_ar._parse_bool(None) is False
        assert radar_ar._parse_bool(None, True) is True

    def test_get_tier_boundaries(self, radar_ar):
        """Test _get_tier_boundaries helper function."""
        cfg = {"tiers": {"tier1_min": 0.05, "tier1_max": 0.33, "tier2_max": 0.66}}
        t1_min, t1_max, t2_max = radar_ar._get_tier_boundaries(cfg)
        assert t1_min == 0.05
        assert t1_max == 0.33
        assert t2_max == 0.66

    def test_get_tier_boundaries_defaults(self, radar_ar):
        """Test _get_tier_boundaries with missing config."""
        cfg = {}
        t1_min, t1_max, t2_max = radar_ar._get_tier_boundaries(cfg)
        assert t1_min == 0.0
        assert t1_max == 0.33
        assert t2_max == 0.66

    def test_get_tier_boundaries_clamping(self, radar_ar):
        """Test _get_tier_boundaries clamping to valid ranges."""
        cfg = {"tiers": {"tier1_min": -0.1, "tier1_max": -0.5, "tier2_max": 1.5}}
        t1_min, t1_max, t2_max = radar_ar._get_tier_boundaries(cfg)
        assert t1_min == 0.0
        assert t1_max >= t1_min
        assert t2_max == 1.0

    def test_get_tier_boundaries_inverted(self, radar_ar):
        """Test _get_tier_boundaries when tier2_max < tier1_max."""
        cfg = {"tiers": {"tier1_min": 0.0, "tier1_max": 0.8, "tier2_max": 0.5}}
        t1_min, t1_max, t2_max = radar_ar._get_tier_boundaries(cfg)
        assert t2_max >= t1_max

    def test_get_tier_boundaries_tier1_min_exceeds_tier1_max(self, radar_ar):
        """Test _get_tier_boundaries when tier1_min > tier1_max forces t1_max up."""
        cfg = {"tiers": {"tier1_min": 0.5, "tier1_max": 0.2, "tier2_max": 0.66}}
        t1_min, t1_max, t2_max = radar_ar._get_tier_boundaries(cfg)
        assert t1_max >= t1_min


class TestActionPlanner:
    """Test suite for ActionPlanner tier-based logic."""

    def _make_decision(self, tier: int, allow_mitigation: bool = False, mitigations_tier2: list = None, mitigations_tier3: list = None):
        return {
            "scenario": {
                "config": {
                    "allow_mitigation": allow_mitigation,
                    "mitigations_tier2": mitigations_tier2 or [],
                    "mitigations_tier3": mitigations_tier3 or [],
                }
            },
            "risk": {"tier": tier},
        }

    def test_tier_0_no_email_no_mitigations(self, radar_ar, mock_logger):
        """Tier 0 should suppress email and produce no mitigations."""
        planner = radar_ar.ActionPlanner(mock_logger)
        planned = planner.plan(self._make_decision(tier=0, allow_mitigation=True, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        assert planned["notify_email"] is False
        assert planned["mitigations"] == []

    def test_tier_1_email_no_mitigations(self, radar_ar, mock_logger):
        """Tier 1 should send email but never trigger mitigations."""
        planner = radar_ar.ActionPlanner(mock_logger)
        planned = planner.plan(self._make_decision(tier=1, allow_mitigation=True, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        assert planned["notify_email"] is True
        assert planned["mitigations"] == []

    def test_tier_2_email_and_mild_mitigations(self, radar_ar, mock_logger):
        """Tier 2 with allow_mitigation=True should send email and trigger only mild mitigations."""
        planner = radar_ar.ActionPlanner(mock_logger)
        planned = planner.plan(self._make_decision(tier=2, allow_mitigation=True, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        assert planned["notify_email"] is True
        assert planned["mitigations"] == ["firewall-drop"]

    def test_tier_2_email_no_mitigations_when_not_allowed(self, radar_ar, mock_logger):
        """Tier 2 with allow_mitigation=False should send email but no mitigations."""
        planner = radar_ar.ActionPlanner(mock_logger)
        planned = planner.plan(self._make_decision(tier=2, allow_mitigation=False, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        assert planned["notify_email"] is True
        assert planned["mitigations"] == []

    def test_tier_3_email_and_harsh_mitigations(self, radar_ar, mock_logger):
        """Tier 3 with allow_mitigation=True should send email and trigger full harsh mitigations."""
        planner = radar_ar.ActionPlanner(mock_logger)
        planned = planner.plan(self._make_decision(tier=3, allow_mitigation=True, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        assert planned["notify_email"] is True
        assert planned["mitigations"] == ["firewall-drop", "lock_user_linux.sh"]

    def test_tier_3_harsh_mitigations_are_superset_of_tier_2(self, radar_ar, mock_logger):
        """Tier 3 mitigations must be a superset of tier 2 mitigations."""
        planner = radar_ar.ActionPlanner(mock_logger)
        t2 = planner.plan(self._make_decision(tier=2, allow_mitigation=True, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        t3 = planner.plan(self._make_decision(tier=3, allow_mitigation=True, mitigations_tier2=["firewall-drop"], mitigations_tier3=["firewall-drop", "lock_user_linux.sh"]))
        assert set(t2["mitigations"]).issubset(set(t3["mitigations"]))


class TestDecipherIncidentGate:
    """Verify that DECIPHER incident creation is gated on tier >= 1 (not tier 0)."""

    def _make_decision(self, radar_ar, tier: int):
        return {
            "decision_id": "abc123",
            "scenario": {
                "name": "suspicious_login",
                "detection": "signature",
                "config": {
                    "allow_mitigation": True,
                    "mitigations_tier2": [],
                    "mitigations_tier3": ["firewall-drop", "lock_user_linux.sh"],
                },
                "alert": {
                    "id": "1",
                    "timestamp": "2025-12-08T13:03:00.000+0000",
                    "rule": {"id": "210020", "level": 10, "description": "test", "groups": []},
                    "agent": {"id": "001", "name": "edge.vm"},
                },
            },
            "context": {"iocs": {}, "window": {}, "effective_agent": "edge.vm", "events": [], "event_count": 0},
            "cti": {"ok": False, "cti_score_T": 0.0, "labels": [], "misp_events": [], "case_id": None, "case_url": None, "raw": None},
            "risk": {"risk_score": 0.5, "tier": tier, "threshold": 0.51, "components": {}},
        }

    def _make_decipher(self, radar_ar):
        mock_logger = unittest.mock.MagicMock()
        decipher = radar_ar.DecipherClient(mock_logger)
        decipher._available = True
        create_calls = []
        decipher.create_incident = lambda d: create_calls.append(d) or {"ok": True, "case_id": "1", "case_url": "http://x/1", "raw": {}}
        return decipher, create_calls

    def test_incident_not_created_at_tier_0(self, radar_ar):
        decipher, create_calls = self._make_decipher(radar_ar)
        decision = self._make_decision(radar_ar, tier=0)
        if decipher.health_check() and decision["risk"]["tier"] >= 1:
            decipher.create_incident(decision)
        assert create_calls == []

    @pytest.mark.parametrize("tier", [1, 2, 3])
    def test_incident_created_at_tier_1_and_above(self, radar_ar, tier):
        decipher, create_calls = self._make_decipher(radar_ar)
        decision = self._make_decision(radar_ar, tier=tier)
        if decipher.health_check() and decision["risk"]["tier"] >= 1:
            decipher.create_incident(decision)
        assert len(create_calls) == 1, f"create_incident must be called exactly once at tier {tier}"

class TestScenarioIdentifier:
    """Test suite for ScenarioIdentifier rule_id and rule_group matching."""

    def test_identify_by_rule_group(self, radar_ar, mock_logger):
        """Test identify matches a scenario by rule_group when the rule_id isn't individually listed."""
        cfg = {
            "scenarios": {
                "default": {"signature": {"rule_groups": ["authentication_failures"]}},
            }
        }
        identifier = radar_ar.ScenarioIdentifier(mock_logger, cfg)
        result = identifier.identify({"rule": {"id": "5760", "groups": ["authentication_failures", "sshd"]}})
        assert result["name"] == "default"
        assert result["detection"] == "signature"
        assert result["matched_by"] == "rule_group"
        assert result["matched_group"] == "authentication_failures"


class TestContextQueryRetry:
    def test_retries_until_events_found(self, radar_ar, mock_logger, monkeypatch):
        monkeypatch.setattr(radar_ar.time, "sleep", lambda _s: None)

        os_client = Mock()
        os_client.indices = "wazuh-alerts-*,wazuh-archives-*"
        os_client.search.side_effect = [[], [], [{"rule": {"id": "100810"}}]]

        strategy = radar_ar.BaseScenario(mock_logger, os_client)
        strategy.context_query_attempts = 3
        strategy.context_query_retry_seconds = 0

        t_start = datetime(2026, 8, 27, 12, 40, tzinfo=timezone.utc)
        t_end = datetime(2026, 8, 27, 12, 45, tzinfo=timezone.utc)
        scenario = {"alert": {}, "config": {}, "name": "default", "detection": "signature"}
        events = strategy._query_events_with_retry(scenario, t_start, t_end, "vm-intern-cyfort-1")

        assert events == [{"rule": {"id": "100810"}}]
        assert os_client.search.call_count == 3

    def test_gives_up_after_configured_attempts(self, radar_ar, mock_logger, monkeypatch):
        monkeypatch.setattr(radar_ar.time, "sleep", lambda _s: None)

        os_client = Mock()
        os_client.indices = "wazuh-alerts-*,wazuh-archives-*"
        os_client.search.return_value = []

        strategy = radar_ar.BaseScenario(mock_logger, os_client)
        strategy.context_query_attempts = 2
        strategy.context_query_retry_seconds = 0

        t_start = datetime(2026, 8, 27, 12, 40, tzinfo=timezone.utc)
        t_end = datetime(2026, 8, 27, 12, 45, tzinfo=timezone.utc)
        scenario = {"alert": {}, "config": {}, "name": "default", "detection": "signature"}
        events = strategy._query_events_with_retry(scenario, t_start, t_end, "vm-intern-cyfort-1")

        assert events == []
        assert os_client.search.call_count == 4

class TestAuditLogFieldNames:
    """SRS-062 requirement #7: the audit entry must carry exactly
    decision_id, rule_id, source_ip, action, tier, result, reason."""

    def test_write_uses_action_field_not_mitigation(self, radar_ar, mock_logger, tmp_path):
        log_path = tmp_path / "active-responses.log"
        audit = radar_ar.AuditLog(mock_logger, log_path)
        audit.write(decision_id="d1", rule_id="100830", source_ip="198.51.100.22",
                    action="firewall-drop", tier=2, result=radar_ar.AuditLog.RESULT_DECLINED,
                    reason="allowlist")

        content = log_path.read_text()
        json_part = content.split(": ", 1)[1]
        import json
        entry = json.loads(json_part)
        assert entry["action"] == "firewall-drop"
        assert "mitigation" not in entry
        assert entry["reason"] == "allowlist"
        assert set(entry.keys()) >= {"decision_id", "rule_id", "source_ip", "action", "tier", "result", "reason"}


@pytest.mark.parametrize("name", ["lock_user_linux.sh", "terminate_service.sh"])
def test_standalone_ar_script_matches_bootstrap_copy(name):
    """The manual-setup copy must not drift from what bootstrap-agent.sh installs."""
    import re
    radar_root = Path(__file__).resolve().parents[2]
    bootstrap = (radar_root / "bootstrap-agent.sh").read_text()
    match = re.search(rf"write_ar_script {re.escape(name)} <<'AR_SCRIPT_EOF'\n(.*?)^AR_SCRIPT_EOF$",
                      bootstrap, re.S | re.M)
    assert match, f"{name} heredoc not found in bootstrap-agent.sh"
    standalone = (radar_root / "scenarios" / "active_responses" / name).read_text()
    assert standalone == match.group(1)


class TestBuildArgsTargetValidation:
    """Mitigation targets come from attacker-influenced alert fields."""

    @staticmethod
    def _build(radar_ar, mock_logger, command, iocs, config=None):
        executor = radar_ar.ActionExecutor(mock_logger, Mock())
        return executor._build_args(command, {"config": config or {}}, iocs)

    def test_lock_user_drops_root_protected_and_malformed_names(self, radar_ar, mock_logger):
        iocs = {"user": ["alice", "ROOT", "admin", "-ohax", "bob; rm -rf /", "../x", "carol.smith"]}
        args = self._build(radar_ar, mock_logger, "lock_user_linux.sh", iocs,
                           {"protected_users": ["Admin"]})
        assert args == [["alice"], ["carol.smith"]]

    def test_terminate_service_refuses_services_not_allowlisted(self, radar_ar, mock_logger):
        iocs = {"service": ["sshd", "wazuh-agent"], "ip": []}
        assert self._build(radar_ar, mock_logger, "terminate_service.sh", iocs) == []

    def test_terminate_service_picks_allowlisted_service(self, radar_ar, mock_logger):
        iocs = {"service": ["sshd", "nginx.service"], "ip": ["203.0.113.7"]}
        args = self._build(radar_ar, mock_logger, "terminate_service.sh", iocs,
                           {"terminable_services": ["nginx"]})
        assert args == [["nginx"]]

    def test_terminate_service_never_uses_scraped_ips(self, radar_ar, mock_logger):
        iocs = {"service": ["sshd"], "ip": ["127.0.0.1", "0.0.0.0", "not-an-ip", "203.0.113.7"]}
        args = self._build(radar_ar, mock_logger, "terminate_service.sh", iocs,
                           {"terminable_services": ["nginx"]})
        assert args == []

    def test_terminate_service_uses_alert_own_ip(self, radar_ar, mock_logger):
        executor = radar_ar.ActionExecutor(mock_logger, Mock())
        iocs = {"service": [], "ip": ["198.51.100.1"]}
        assert executor._build_args("terminate_service.sh", {"config": {}}, iocs, "203.0.113.7") == [["203.0.113.7"]]
        assert executor._build_args("terminate_service.sh", {"config": {}}, iocs, "127.0.0.1") == []

    def test_terminate_service_rejects_path_like_service_even_if_listed(self, radar_ar, mock_logger):
        iocs = {"service": ["../../tmp/x"], "ip": []}
        args = self._build(radar_ar, mock_logger, "terminate_service.sh", iocs,
                           {"terminable_services": ["../../tmp/x"]})
        assert args == []


class TestNeverBlockAndAlertOwnTarget:

    def _executor(self, radar_ar, mock_logger, cfg=None, env=None, monkeypatch=None):
        if monkeypatch:
            for k in ("RADAR_MANAGER_ADDRESS", "OS_URL", "WAZUH_API_URL"):
                monkeypatch.delenv(k, raising=False)
            for k, v in (env or {}).items():
                monkeypatch.setenv(k, v)
        nb = radar_ar.NeverBlock(mock_logger, cfg or {}, use_env=bool(env))
        return radar_ar.ActionExecutor(mock_logger, Mock(), never_block=nb)

    def test_firewall_drop_uses_alert_ip(self, radar_ar, mock_logger):
        ex = self._executor(radar_ar, mock_logger)
        assert ex._build_args("firewall-drop", {"config": {}}, {"ip": ["198.51.100.9"]}, "203.0.113.7") == [["203.0.113.7"]]

    def test_firewall_drop_never_uses_scraped_ip(self, radar_ar, mock_logger):
        ex = self._executor(radar_ar, mock_logger)
        assert ex._build_args("firewall-drop", {"config": {}}, {"ip": ["198.51.100.9"]}, "") == []
        assert ex.last_refusal == "no_alert_source_ip"

    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "not-an-ip"])
    def test_firewall_drop_refuses_protected_defaults(self, radar_ar, mock_logger, ip):
        ex = self._executor(radar_ar, mock_logger)
        assert ex._build_args("firewall-drop", {"config": {}}, {}, ip) == []

    def test_configured_never_block_cidr(self, radar_ar, mock_logger):
        ex = self._executor(radar_ar, mock_logger, {"global": {"never_block": ["10.0.0.0/24", "2001:db8::/32"]}})
        assert ex._build_args("firewall-drop", {"config": {}}, {}, "10.0.0.1") == []
        assert ex.last_refusal == "never_block"
        assert ex._build_args("firewall-drop", {"config": {}}, {}, "2001:db8::5") == []
        assert ex._build_args("firewall-drop", {"config": {}}, {}, "10.0.1.1") == [["10.0.1.1"]]

    def test_manager_and_indexer_addresses_are_protected(self, radar_ar, mock_logger, monkeypatch):
        ex = self._executor(radar_ar, mock_logger, env={"RADAR_MANAGER_ADDRESS": "192.0.2.10",
                                                        "OS_URL": "https://192.0.2.11:9200",
                                                        "WAZUH_API_URL": "https://localhost:55000"},
                            monkeypatch=monkeypatch)
        for ip in ("192.0.2.10", "192.0.2.11"):
            assert ex._build_args("firewall-drop", {"config": {}}, {}, ip) == []

    def test_terminate_service_ip_path_respects_never_block(self, radar_ar, mock_logger):
        ex = self._executor(radar_ar, mock_logger, {"global": {"never_block": ["203.0.113.0/24"]}})
        assert ex._build_args("terminate_service.sh", {"config": {}}, {"service": [], "ip": []}, "203.0.113.7") == []

    def test_resolve_target_ip_has_no_scraped_fallback(self, radar_ar, mock_logger):
        strat = radar_ar.BaseScenario(mock_logger, Mock())
        scenario = {"alert": {"data": {}}}
        assert strat.resolve_target_ip(scenario, {"iocs": {"ip": ["203.0.113.7"]}}) is None

    def test_invalid_config_entry_is_ignored(self, radar_ar, mock_logger):
        nb = radar_ar.NeverBlock(mock_logger, {"global": {"never_block": ["nonsense", "10.1.0.0/16"]}}, use_env=False)
        assert nb.contains("10.1.2.3") and not nb.contains("10.2.0.1")


class TestScanningXff:
    @pytest.mark.parametrize("proxies,data,expected", [
        ([], {"src_ip": "198.51.100.1", "http": {"xff": "10.0.0.1"}}, "198.51.100.1"),
        (["198.51.100.0/24"], {"src_ip": "198.51.100.1", "http": {"xff": "203.0.113.9"}}, "203.0.113.9"),
        (["198.51.100.0/24"], {"src_ip": "198.51.100.1", "http": {"xff": "10.0.0.1, 203.0.113.9"}}, "203.0.113.9"),
        (["198.51.100.0/24"], {"src_ip": "198.51.100.1", "http": {"xff": "203.0.113.9, 198.51.100.2"}}, "203.0.113.9"),
        (["198.51.100.0/24"], {"src_ip": "192.0.2.50", "http": {"xff": "10.0.0.1"}}, "192.0.2.50"),
        (["198.51.100.0/24"], {"src_ip": "198.51.100.1", "http": {"xff": "garbage"}}, "198.51.100.1"),
    ])
    def test_xff_only_from_trusted_proxy(self, radar_ar, mock_logger, proxies, data, expected):
        strat = radar_ar.ScanningDetection(mock_logger, Mock())
        scenario = {"alert": {"data": data}, "config": {"trusted_proxies": proxies}}
        assert strat.resolve_target_ip(scenario, {}) == expected


class TestAdAlertOrigin:

    @pytest.mark.parametrize("agent,location,ok", [
        ("ad-webhook", "/var/log/ad_alerts.log", True),
        ("ad-webhook", "(ad-webhook) any->/var/log/ad_alerts.log", True),
        ("db01", "/var/log/auth.log", False),
        ("db01", "/var/log/ad_alerts.log", False),
        ("ad-webhook", "/var/log/syslog", False),
        ("ad-webhook", "/tmp/var/log/ad_alerts.log.x", False),
        ("", "", False),
    ])
    def test_verify(self, radar_ar, mock_logger, monkeypatch, agent, location, ok):
        monkeypatch.delenv("WEBHOOK_AGENT_NAME", raising=False)
        alert = {"agent": {"name": agent}, "location": location}
        assert radar_ar.AdAlertOrigin.verify(alert, mock_logger) is ok

    def test_agent_name_is_configurable(self, radar_ar, mock_logger, monkeypatch):
        monkeypatch.setenv("WEBHOOK_AGENT_NAME", "hook2")
        alert = {"agent": {"name": "hook2"}, "location": "/var/log/ad_alerts.log"}
        assert radar_ar.AdAlertOrigin.verify(alert, mock_logger)


class TestLogVolumeWindowClamp:
    def _window(self, radar_ar, mock_logger, ps, pe, ts="2026-09-24T12:00:00+00:00", delta=10):
        strat = radar_ar.LogVolume(mock_logger, Mock())
        scenario = {"alert": {"timestamp": ts, "data": {"period_start": ps, "period_end": pe}},
                    "config": {"delta_ad_minutes": delta}, "detection": "ad"}
        return strat.resolve_time_window(scenario)

    def test_normal_period_is_kept(self, radar_ar, mock_logger):
        s, e = self._window(radar_ar, mock_logger, "2026-09-24T11:50:00Z", "2026-09-24T11:59:00Z")
        assert (s.minute, e.minute) == (50, 59)

    def test_long_period_is_capped_at_delta(self, radar_ar, mock_logger):
        s, e = self._window(radar_ar, mock_logger, "2026-09-01T00:00:00Z", "2026-09-24T11:59:00Z")
        assert e - s == radar_ar.timedelta(minutes=10)

    def test_future_end_is_clamped_to_alert_time(self, radar_ar, mock_logger):
        s, e = self._window(radar_ar, mock_logger, "2026-09-24T11:55:00Z", "2027-01-01T00:00:00Z")
        assert e.isoformat() == "2026-09-24T12:00:00+00:00"

    def test_inverted_period_falls_back(self, radar_ar, mock_logger):
        s, e = self._window(radar_ar, mock_logger, "2026-09-24T11:59:00Z", "2026-09-24T11:00:00Z")
        assert e.isoformat() == "2026-09-24T12:00:00+00:00" and e - s == radar_ar.timedelta(minutes=10)


def test_rule_100300_is_restricted_to_webhook_log():
    import xml.etree.ElementTree as ET
    root = Path(__file__).resolve().parents[2]
    text = next((root / "scenarios" / "rules" / "log_volume").glob("*.xml")).read_text()
    tree = ET.fromstring("<r>" + text + "</r>")
    rule = next(r for r in tree.iter("rule") if r.get("id") == "100300")
    assert rule.findtext("location") == "/var/log/ad_alerts.log$"



class TestActiveResponsePayload:
    def _run(self, radar_ar, mock_logger, command, target_ip, iocs=None):
        api = Mock()
        api.get_agent_id_by_name.return_value = "002"
        ex = radar_ar.ActionExecutor(mock_logger, api)
        decision = {
            "scenario": {"config": {}, "alert": {"agent": {"id": "002", "name": "web01"},
                                                 "data": {"src_ip": "198.51.100.9", "srcip": "10.0.0.9",
                                                          "http": {"xff": "10.0.0.8"}}}},
            "context": {"iocs": iocs or {}, "effective_agent": "web01"},
            "target_ip": target_ip,
        }
        ex._execute_mitigation(decision, command)
        return api.send_active_response.call_args

    def test_firewall_drop_receives_only_the_checked_ip(self, radar_ar, mock_logger):
        call = self._run(radar_ar, mock_logger, "firewall-drop", "203.0.113.7")
        agent_id, command, args, alert_data = call.args
        assert (agent_id, command, args) == ("002", "!firewall-drop", ["203.0.113.7"])
        assert alert_data == {"srcip": "203.0.113.7"}

    def test_other_commands_receive_no_alert_data(self, radar_ar, mock_logger):
        call = self._run(radar_ar, mock_logger, "lock_user_linux.sh", "", {"user": ["bob"]})
        assert call.args[2] == ["bob"] and call.args[3] == {}

    def test_payload_shape(self, radar_ar, mock_logger):
        client = radar_ar.WazuhApiClient.__new__(radar_ar.WazuhApiClient)
        client.base_url, client.verify_ssl, client.timeout = "https://m:55000", False, 5
        client.logger = mock_logger
        client._authenticate = lambda: "tok"
        client._requests = Mock()
        client._requests.put.return_value.json.return_value = {}
        client.send_active_response("002", "!firewall-drop", ["203.0.113.7"], {"srcip": "203.0.113.7"})
        body = json.loads(client._requests.put.call_args.kwargs["data"])
        assert body == {"command": "!firewall-drop", "arguments": ["203.0.113.7"],
                        "alert": {"data": {"srcip": "203.0.113.7"}}}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])