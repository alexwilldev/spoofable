"""
Tests for the grading logic.

These are the tests that matter most, because grade() is where the
project makes a claim about the real world. A bug in the DNS client
produces an obvious failure; a bug here produces a confident, wrong,
plausible-looking answer.
"""

from __future__ import annotations

from spoofable import dmarc as dmarc_mod
from spoofable import spf as spf_mod
from spoofable.audit import ERROR, PROTECTED, SPOOFABLE, WEAK, grade, summarize


def make_spf(record=None, lookup_failed=False):
    if lookup_failed:
        result = spf_mod.SpfRecord(domain="x.com")
        result.lookup_failed = True
        return result
    return spf_mod.analyze("x.com", txt_values=[record] if record else [])


def make_dmarc(record=None, lookup_failed=False):
    if lookup_failed:
        result = dmarc_mod.DmarcRecord(domain="x.com")
        result.lookup_failed = True
        return result
    return dmarc_mod.analyze("x.com", txt_values=[record] if record else [])


class TestSpoofable:
    def test_no_dmarc_record(self):
        result = grade("x.com", make_spf("v=spf1 -all"), make_dmarc())
        assert result.verdict == SPOOFABLE
        assert "no DMARC record" in result.reason

    def test_p_none(self):
        result = grade(
            "x.com", make_spf("v=spf1 -all"), make_dmarc("v=DMARC1; p=none")
        )
        assert result.verdict == SPOOFABLE

    def test_perfect_spf_does_not_rescue_a_missing_dmarc(self):
        """
        The central point of the whole project. SPF validates the
        envelope sender; the mail client displays the From: header.
        Without DMARC nothing ties the two together, so an immaculate
        SPF record still leaves the domain fully spoofable.
        """
        result = grade("x.com", make_spf("v=spf1 ip4:1.2.3.4 -all"), make_dmarc())
        assert result.verdict == SPOOFABLE

    def test_invalid_dmarc_record(self):
        result = grade(
            "x.com", make_spf("v=spf1 -all"), make_dmarc("v=DMARC1; rua=mailto:a@x.com")
        )
        assert result.verdict == SPOOFABLE

    def test_spf_plus_all_overrides_a_good_dmarc(self):
        result = grade(
            "x.com", make_spf("v=spf1 +all"), make_dmarc("v=DMARC1; p=reject")
        )
        assert result.verdict == SPOOFABLE


class TestWeak:
    def test_quarantine(self):
        result = grade(
            "x.com", make_spf("v=spf1 -all"), make_dmarc("v=DMARC1; p=quarantine")
        )
        assert result.verdict == WEAK

    def test_partial_percentage(self):
        result = grade(
            "x.com", make_spf("v=spf1 -all"), make_dmarc("v=DMARC1; p=reject; pct=10")
        )
        assert result.verdict == WEAK
        assert "10%" in result.reason

    def test_subdomain_policy_none(self):
        result = grade(
            "x.com", make_spf("v=spf1 -all"), make_dmarc("v=DMARC1; p=reject; sp=none")
        )
        assert result.verdict == WEAK
        assert "subdomain" in result.reason

    def test_no_spf_with_enforcing_dmarc(self):
        result = grade("x.com", make_spf(), make_dmarc("v=DMARC1; p=reject"))
        assert result.verdict == WEAK
        assert "DKIM" in result.reason

    def test_spf_lookup_failure_does_not_claim_absence(self):
        result = grade(
            "x.com", make_spf(lookup_failed=True), make_dmarc("v=DMARC1; p=reject")
        )
        assert result.verdict == WEAK
        assert "could not be retrieved" in result.reason


class TestProtected:
    def test_reject_at_full_percentage(self):
        result = grade(
            "x.com",
            make_spf("v=spf1 ip4:1.2.3.4 -all"),
            make_dmarc("v=DMARC1; p=reject; rua=mailto:a@x.com"),
        )
        assert result.verdict == PROTECTED

    def test_softfail_spf_is_still_protected_when_dmarc_rejects(self):
        # ~all is fine under DMARC: alignment is what counts, and a
        # softfail still fails, which is all DMARC needs.
        result = grade(
            "x.com",
            make_spf("v=spf1 ip4:1.2.3.4 ~all"),
            make_dmarc("v=DMARC1; p=reject; rua=mailto:a@x.com"),
        )
        assert result.verdict == PROTECTED


class TestError:
    def test_dmarc_lookup_failure_is_not_a_finding(self):
        result = grade("x.com", make_spf(lookup_failed=True), make_dmarc(lookup_failed=True))
        assert result.verdict == ERROR
        assert "could not be assessed" in result.reason


class TestSummarize:
    def test_percentages_exclude_errors(self):
        results = [
            grade("a.com", make_spf("v=spf1 -all"), make_dmarc()),                      # SPOOFABLE
            grade("b.com", make_spf("v=spf1 -all"), make_dmarc("v=DMARC1; p=quarantine")),  # WEAK
            grade("c.com", make_spf("v=spf1 -all"),
                  make_dmarc("v=DMARC1; p=reject; rua=mailto:a@x.com")),                # PROTECTED
            grade("d.com", make_spf(lookup_failed=True), make_dmarc(lookup_failed=True)),  # ERROR
        ]
        stats = summarize(results)

        assert stats["total"] == 4
        assert stats["assessed"] == 3
        assert stats["spoofable"] == 1
        assert abs(stats["spoofable_pct"] - 33.33) < 0.1

    def test_empty_input_does_not_divide_by_zero(self):
        stats = summarize([])
        assert stats["spoofable_pct"] == 0.0
