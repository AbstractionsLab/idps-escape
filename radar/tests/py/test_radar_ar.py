#!/usr/bin/env python3
"""
Unit tests for RADAR Active Response script (radar_ar.py)
Tests the RiskEngine class and its risk calculation logic.
"""

import sys
import types
import pytest
import importlib.util
import importlib.machinery
from pathlib import Path
from unittest.mock import Mock, MagicMock


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

    def test_compute_cti_score_no_hits(self, risk_engine):
        """Test _compute_cti_score with no CTI hits."""
        cti = {}
        
        score = risk_engine._compute_cti_score(cti)
        assert score == 0.0

    def test_compute_cti_score_malicious_only(self, risk_engine):
        """Test _compute_cti_score with malicious flag and confidence."""
        cti = {"malicious": True, "confidence": 0.9}
        
        score = risk_engine._compute_cti_score(cti)
        # T = 1 - (1 - 0.9) = 0.9
        assert score == pytest.approx(0.9, abs=0.001)

    def test_compute_cti_score_ip_blacklisted(self, risk_engine):
        """Test _compute_cti_score with IP blacklisted."""
        cti = {"matched_iocs": {"ip": ["192.168.1.1"]}}
        
        score = risk_engine._compute_cti_score(cti)
        # T = 1 - (1 - 0.6) = 0.6 (default weight for ip_blacklisted)
        assert score == pytest.approx(0.6, abs=0.001)

    def test_compute_cti_score_multiple_iocs(self, risk_engine):
        """Test _compute_cti_score with multiple IOC types."""
        cti = {
            "matched_iocs": {
                "ip": ["192.168.1.1"],
                "domain": ["evil.com"]
            }
        }
        
        score = risk_engine._compute_cti_score(cti)
        # T = 1 - (1 - 0.6) * (1 - 0.4) = 1 - 0.4 * 0.6 = 1 - 0.24 = 0.76
        assert score == pytest.approx(0.76, abs=0.001)

    def test_compute_cti_score_all_iocs(self, risk_engine):
        """Test _compute_cti_score with all IOC types."""
        cti = {
            "malicious": True,
            "confidence": 0.9,
            "matched_iocs": {
                "ip": ["192.168.1.1"],
                "domain": ["evil.com"],
                "hash": ["abc123"],
                "user": ["malicious_user"]
            }
        }
        
        score = risk_engine._compute_cti_score(cti)
        # T = 1 - (1-0.9) * (1-0.6) * (1-0.4) * (1-0.7) * (1-0.5)
        # T = 1 - 0.1 * 0.4 * 0.6 * 0.3 * 0.5
        # T = 1 - 0.0036 = 0.9964
        assert score == pytest.approx(0.9964, abs=0.001)

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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "100900"}}
        }
        cti = {}
        
        result = risk_engine.compute(scenario, cti, None, None)
        
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "100309"}}
        }
        cti = {}
        ad_grade = 0.62
        ad_conf = 0.74
        
        result = risk_engine.compute(scenario, cti, ad_grade, ad_conf)
        
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "210012"}}
        }
        cti = {"malicious": True, "confidence": 0.8}
        ad_grade = 0.60
        ad_conf = 0.70
        
        result = risk_engine.compute(scenario, cti, ad_grade, ad_conf)
        
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        cti = {
            "matched_iocs": {
                "ip": ["1.2.3.4"],
                "domain": ["evil.com"]
            }
        }
        ad_grade = 0.62
        ad_conf = 0.74
        
        result = risk_engine.compute(scenario, cti, ad_grade, ad_conf)
        
        # From spec:
        # A = 0.62 * 0.74 = 0.4588
        # S = 0.4 * 0.9 = 0.36
        # T = 1 - (1-0.6)*(1-0.4) = 0.76
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        cti = {}
        
        result = risk_engine.compute(scenario, cti, None, None)
        
        # S = 0.2 * 0.5 = 0.1
        # R = 1.0 * 0.1 = 0.1 < 0.33
        assert result["risk_score"] == 0.1
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        cti = {"malicious": True, "confidence": 1.0}
        ad_grade = 0.9
        ad_conf = 0.9
        
        result = risk_engine.compute(scenario, cti, ad_grade, ad_conf)
        
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        cti = {"malicious": True, "confidence": 1.0}
        
        result = risk_engine.compute(scenario, cti, None, None)
        
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
                "tiers": {"tier1_max": 0.33, "tier2_max": 0.66}
            },
            "alert": {"rule": {"id": "test"}}
        }
        cti = {"malicious": True, "confidence": 0.5}
        ad_grade = 0.6
        ad_conf = 0.7
        
        result = risk_engine.compute(scenario, cti, ad_grade, ad_conf)
        
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
        cfg = {"tiers": {"tier1_max": 0.33, "tier2_max": 0.66}}
        t1, t2 = radar_ar._get_tier_boundaries(cfg)
        assert t1 == 0.33
        assert t2 == 0.66

    def test_get_tier_boundaries_defaults(self, radar_ar):
        """Test _get_tier_boundaries with missing config."""
        cfg = {}
        t1, t2 = radar_ar._get_tier_boundaries(cfg)
        assert t1 == 0.33
        assert t2 == 0.66

    def test_get_tier_boundaries_clamping(self, radar_ar):
        """Test _get_tier_boundaries clamping to valid ranges."""
        cfg = {"tiers": {"tier1_max": -0.5, "tier2_max": 1.5}}
        t1, t2 = radar_ar._get_tier_boundaries(cfg)
        assert t1 == 0.0  # Clamped from -0.5
        assert t2 == 1.0  # Clamped from 1.5

    def test_get_tier_boundaries_inverted(self, radar_ar):
        """Test _get_tier_boundaries when tier2_max < tier1_max."""
        cfg = {"tiers": {"tier1_max": 0.8, "tier2_max": 0.5}}
        t1, t2 = radar_ar._get_tier_boundaries(cfg)
        assert t2 >= t1  # Should be corrected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
