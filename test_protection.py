"""
Tests for critical signature protection logic.
These ensure that high-severity CVE signatures can never be auto-suppressed.
"""

import pytest

# SIDs that must never be suppressed under any circumstances
CRITICAL_SIDS = {
    2034131,  # Log4Shell CVE-2021-44228
    2031412,  # ProxyLogon CVE-2021-26855
    2031900,  # ZeroLogon CVE-2020-1472
    2031449,  # SUNBURST
    2033462,  # PrintNightmare CVE-2021-34527
    2036000,  # Spring4Shell CVE-2022-22965
}


def is_critical(sid: int, critical_sids: set) -> bool:
    """Return True if a SID is on the never-suppress list."""
    return sid in critical_sids


def should_suppress(sid: int, alert_rate_per_hour: float, critical_sids: set, fp_threshold: float = 50.0) -> bool:
    """
    Determine if a rule should be auto-suppressed.
    Returns False for any critical SID regardless of alert rate.
    """
    if is_critical(sid, critical_sids):
        return False
    return alert_rate_per_hour >= fp_threshold


class TestCriticalProtection:

    def test_log4shell_never_suppressed(self):
        """Log4Shell must never be suppressed even at extreme alert rates."""
        assert should_suppress(2034131, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False

    def test_proxylogon_never_suppressed(self):
        assert should_suppress(2031412, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False

    def test_zerologon_never_suppressed(self):
        assert should_suppress(2031900, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False

    def test_sunburst_never_suppressed(self):
        assert should_suppress(2031449, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False

    def test_printnightmare_never_suppressed(self):
        assert should_suppress(2033462, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False

    def test_spring4shell_never_suppressed(self):
        assert should_suppress(2036000, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False

    def test_all_critical_sids_protected(self):
        """Every SID in CRITICAL_SIDS must be blocked from suppression."""
        for sid in CRITICAL_SIDS:
            assert should_suppress(sid, alert_rate_per_hour=99999, critical_sids=CRITICAL_SIDS) is False, \
                f"SID {sid} should be protected but was not"


class TestFalsePositiveClassification:

    def test_high_rate_non_critical_suppressed(self):
        """A non-critical rule firing 100x/hour should be suppressed."""
        assert should_suppress(9999999, alert_rate_per_hour=100, critical_sids=CRITICAL_SIDS) is True

    def test_low_rate_non_critical_not_suppressed(self):
        """A non-critical rule firing 10x/hour should not be suppressed."""
        assert should_suppress(9999999, alert_rate_per_hour=10, critical_sids=CRITICAL_SIDS) is False

    def test_exactly_at_threshold_suppressed(self):
        """A rule firing exactly at threshold should be suppressed."""
        assert should_suppress(9999999, alert_rate_per_hour=50, critical_sids=CRITICAL_SIDS) is True

    def test_just_below_threshold_not_suppressed(self):
        """A rule firing just below threshold should not be suppressed."""
        assert should_suppress(9999999, alert_rate_per_hour=49.9, critical_sids=CRITICAL_SIDS) is False


class TestIsCritical:

    def test_known_critical_sid(self):
        assert is_critical(2034131, CRITICAL_SIDS) is True

    def test_unknown_sid_not_critical(self):
        assert is_critical(1234567, CRITICAL_SIDS) is False

    def test_empty_critical_list(self):
        assert is_critical(2034131, set()) is False
