"""Tests for SPF parsing and evaluation. All offline."""

from __future__ import annotations

import pytest

from spoofable import spf
from spoofable.spf import analyze, count_lookups, find_spf_record, parse_all_qualifier


class TestFindSpfRecord:
    def test_picks_spf_out_of_the_junk_drawer(self):
        txt = [
            "google-site-verification=abc123",
            "v=spf1 include:_spf.google.com ~all",
            "docusign=05958488-4752",
        ]
        assert find_spf_record(txt) == ["v=spf1 include:_spf.google.com ~all"]

    def test_version_token_is_case_insensitive(self):
        assert find_spf_record(["V=SPF1 -all"]) == ["V=SPF1 -all"]

    def test_no_spf_record(self):
        assert find_spf_record(["google-site-verification=abc"]) == []

    def test_does_not_match_a_record_merely_containing_spf(self):
        assert find_spf_record(["some-vendor=v=spf1 fake"]) == []


class TestParseAllQualifier:
    @pytest.mark.parametrize(
        "record,expected",
        [
            ("v=spf1 -all", "-"),
            ("v=spf1 ~all", "~"),
            ("v=spf1 ?all", "?"),
            ("v=spf1 +all", "+"),
            ("v=spf1 include:x.com -all", "-"),
            ("v=spf1 include:x.com", None),
        ],
    )
    def test_qualifiers(self, record, expected):
        assert parse_all_qualifier(record) == expected

    def test_bare_all_defaults_to_plus(self):
        # The trap: '+' is the default qualifier, so a bare 'all'
        # authorises the entire internet.
        assert parse_all_qualifier("v=spf1 include:x.com all") == "+"

    def test_does_not_match_mechanisms_ending_in_all(self):
        assert parse_all_qualifier("v=spf1 include:sendall.com") is None


class TestCountLookups:
    def test_mechanisms_without_lookups_cost_nothing(self):
        assert count_lookups("x.com", "v=spf1 ip4:1.2.3.4 ip6:::1 -all") == 0

    def test_a_and_mx_each_cost_one(self):
        assert count_lookups("x.com", "v=spf1 a mx -all") == 2

    def test_include_costs_one_plus_whatever_it_contains(self, monkeypatch):
        # Nested record itself uses two lookups, plus one for the
        # include that reached it.
        monkeypatch.setattr(
            spf, "query_txt", lambda name, **kw: ["v=spf1 a mx -all"]
        )
        assert count_lookups("x.com", "v=spf1 include:nested.com -all") == 3

    def test_include_loop_terminates(self, monkeypatch):
        # A record that includes itself must not recurse forever.
        monkeypatch.setattr(
            spf, "query_txt", lambda name, **kw: ["v=spf1 include:loop.com -all"]
        )
        assert count_lookups("loop.com", "v=spf1 include:loop.com -all") <= 12

    def test_unresolvable_include_still_counts(self, monkeypatch):
        def boom(name, **kw):
            raise spf.DnsError("nope")

        monkeypatch.setattr(spf, "query_txt", boom)
        assert count_lookups("x.com", "v=spf1 include:gone.com -all") == 1


class TestAnalyze:
    def test_no_record(self):
        result = analyze("x.com", txt_values=["unrelated=1"])
        assert result.found is False
        assert result.lookup_failed is False
        assert "no SPF record published" in result.warnings

    def test_plus_all_is_an_error(self):
        result = analyze("x.com", txt_values=["v=spf1 +all"])
        assert result.all_qualifier == "+"
        assert any("+all" in e for e in result.errors)

    def test_duplicate_records_are_an_error(self):
        result = analyze("x.com", txt_values=["v=spf1 -all", "v=spf1 ~all"])
        assert result.duplicate_records == 2
        assert result.is_permerror is True

    def test_hard_fail_record_is_clean(self, monkeypatch):
        monkeypatch.setattr(spf, "query_txt", lambda name, **kw: [])
        result = analyze("x.com", txt_values=["v=spf1 ip4:1.2.3.4 -all"])
        assert result.found is True
        assert result.all_meaning == "fail"
        assert result.errors == []

    def test_exceeding_the_lookup_limit_is_an_error(self, monkeypatch):
        monkeypatch.setattr(spf, "query_txt", lambda name, **kw: [])
        record = "v=spf1 " + " ".join("include:v%d.com" % i for i in range(12)) + " -all"
        result = analyze("x.com", txt_values=[record])

        assert result.dns_lookups > 10
        assert result.lookup_limit_exceeded is True
        assert result.is_permerror is True

    def test_lookup_failure_is_not_the_same_as_no_record(self, monkeypatch):
        """
        The bug this test exists to prevent: reporting "no SPF record"
        when the query never got an answer. Absence of evidence is not
        evidence of absence.
        """
        def boom(name, **kw):
            raise spf.DnsError("timed out")

        monkeypatch.setattr(spf, "query_txt", boom)
        result = analyze("x.com")

        assert result.lookup_failed is True
        assert result.found is False
        assert "no SPF record published" not in result.warnings
