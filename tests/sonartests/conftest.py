"""Shared pytest configuration for SONAR tests."""


def pytest_configure(config):
    """Register SONAR markers."""
    config.addinivalue_line("markers", "slow: uses the real MVAD library (imports torch); deselect with -m 'not slow'")
