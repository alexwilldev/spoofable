"""Tests for DMARC parsing and evaluation. All offline."""

from __future__ import annotations

from spoofable import dmarc
from spoofable.dmarc import analyze, parse_tags


class TestParseTags:
    def test_basic_record(self):
        tags = parse_tags("v=DMARC1; p=reject; rua=mailto:x@y.com")
        assert tags["v"] == "dmarc1"
        assert tags["p"] == "reject"
        assert tags["rua"] == "mailto:x@y.com"

    def test_whitespace_and_trailing_semicolon(self):
        assert parse_tags("v=DMARC1 ;  p=none ;")["p"] == "none"

    def test_reporting_addresses_keep_their_case(self):
        tags = parse_tags("v=DMARC1; p=none; rua=mailto:HostMaster@Example.COM")
        assert tags["rua"] == "mailto:HostMaster@Example.COM"

    def test_malformed_fragments_are_skipped(self):
        tags = parse_tags("v=DMARC1; garbage; p=reject")
        assert tags["p"] == "reject"
        assert "garbage" not in tags


class TestAnalyze:
    def test_no_record_means_unprotected(self):
        result = analyze("x.com", txt_values=[])
        assert result.found is False
        assert result.effective_policy == "none"
        assert result.enforced is False

    def test_reject_policy(self):
        result = analyze(
            "x.com", txt_values=["v=DMARC1; p=reject; rua=mailto:a@x.com"]
        )
        assert result.policy == "reject"
        assert result.enforced is True
        assert result.percent == 100
        assert result.rua == ["a@x.com"]

    def test_p_none_warns_that_it_protects_nothing(self):
        result = analyze("x.com", txt_values=["v=DMARC1; p=none; rua=mailto:a@x.com"])
        assert result.policy == "none"
        assert result.enforced is False
        assert any("monitoring only" in w for w in result.warnings)

    def test_partial_percentage_is_flagged(self):
        result = analyze(
            "x.com", txt_values=["v=DMARC1; p=reject; pct=10; rua=mailto:a@x.com"]
        )
        assert result.percent == 10
        assert any("10%" in w for w in result.warnings)

    def test_subdomain_policy_none_is_flagged(self):
        result = analyze(
            "x.com", txt_values=["v=DMARC1; p=reject; sp=none; rua=mailto:a@x.com"]
        )
        assert result.subdomain_policy == "none"
        assert any("subdomain" in w for w in result.warnings)

    def test_missing_policy_tag_is_an_error(self):
        result = analyze("x.com", txt_values=["v=DMARC1; rua=mailto:a@x.com"])
        assert result.policy is None
        assert any("no p= tag" in e for e in result.errors)

    def test_duplicate_records_are_an_error(self):
        result = analyze(
            "x.com", txt_values=["v=DMARC1; p=reject", "v=DMARC1; p=none"]
        )
        assert result.duplicate_records == 2
        assert any("multiple" in e.lower() or "2 DMARC" in e for e in result.errors)

    def test_missing_rua_is_flagged(self):
        result = analyze("x.com", txt_values=["v=DMARC1; p=reject"])
        assert result.has_reporting is False
        assert any("rua" in w for w in result.warnings)

    def test_non_dmarc_txt_records_are_ignored(self):
        result = analyze("x.com", txt_values=["google-site-verification=abc"])
        assert result.found is False

    def test_lookup_failure_is_not_the_same_as_no_record(self, monkeypatch):
        def boom(name, **kw):
            raise dmarc.DnsError("timed out")

        monkeypatch.setattr(dmarc, "query_txt", boom)
        result = analyze("x.com")

        assert result.lookup_failed is True
        assert result.found is False
