"""
Tests for the hand-rolled DNS client.

Everything here runs offline against packets built in the test itself,
so the suite passes with the network disconnected. That matters: a test
suite that needs the internet is a test suite that fails for reasons
unrelated to the code.
"""

from __future__ import annotations

import struct

import pytest

from spoofable.dns_client import (
    TYPE_TXT,
    DnsError,
    DnsResponse,
    _parse_response,
    _skip_name,
    encode_name,
)


class TestEncodeName:
    def test_simple_name(self):
        assert encode_name("example.com") == b"\x07example\x03com\x00"

    def test_subdomain(self):
        assert encode_name("_dmarc.example.com") == b"\x06_dmarc\x07example\x03com\x00"

    def test_trailing_dot_is_ignored(self):
        assert encode_name("example.com.") == encode_name("example.com")

    def test_root(self):
        assert encode_name("") == b"\x00"

    def test_label_over_63_bytes_is_rejected(self):
        with pytest.raises(ValueError):
            encode_name("a" * 64 + ".com")


class TestSkipName:
    def test_skips_uncompressed_name(self):
        packet = b"\x07example\x03com\x00REST"
        assert _skip_name(packet, 0) == len(b"\x07example\x03com\x00")

    def test_pointer_ends_the_name_after_two_bytes(self):
        # 0xC00C is a compression pointer to offset 12.
        packet = b"\xc0\x0c" + b"REST"
        assert _skip_name(packet, 0) == 2

    def test_truncated_name_raises(self):
        with pytest.raises(DnsError):
            _skip_name(b"\x07exa", 0)


def build_response(
    answers, rcode=0, truncated=False, qname="example.com", qtype=TYPE_TXT
):
    """Assemble a DNS response packet for testing."""
    flags = 0x8180 | rcode
    if truncated:
        flags |= 1 << 9

    packet = struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    packet += encode_name(qname) + struct.pack("!HH", qtype, 1)

    for rdata in answers:
        packet += b"\xc0\x0c"  # pointer back to the question name
        packet += struct.pack("!HHIH", qtype, 1, 300, len(rdata))
        packet += rdata

    return packet


def txt_rdata(*strings):
    """Encode TXT rdata: a sequence of length-prefixed character strings."""
    out = b""
    for s in strings:
        raw = s.encode()
        assert len(raw) <= 255
        out += bytes([len(raw)]) + raw
    return out


class TestParseResponse:
    def test_single_txt_record(self):
        packet = build_response([txt_rdata("v=spf1 -all")])
        rcode, truncated, records = _parse_response(packet, TYPE_TXT)

        assert rcode == 0
        assert truncated is False
        assert len(records) == 1

    def test_truncation_flag_is_surfaced(self):
        # The case that silently breaks naive clients: a response with
        # the TC bit set and no answers at all.
        packet = build_response([], truncated=True)
        _rcode, truncated, records = _parse_response(packet, TYPE_TXT)

        assert truncated is True
        assert records == []

    def test_nxdomain_is_reported_not_raised(self):
        packet = build_response([], rcode=3)
        rcode, _truncated, records = _parse_response(packet, TYPE_TXT)

        assert rcode == 3
        assert records == []

    def test_records_of_other_types_are_ignored(self):
        # A CNAME in the answer section must not be mistaken for a TXT.
        packet = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        packet += encode_name("example.com") + struct.pack("!HH", TYPE_TXT, 1)
        packet += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 300, 2) + b"\xc0\x0c"

        _rcode, _truncated, records = _parse_response(packet, TYPE_TXT)
        assert records == []

    def test_short_packet_raises(self):
        with pytest.raises(DnsError):
            _parse_response(b"\x00\x01", TYPE_TXT)

    def test_datagram_cut_mid_record_raises_rather_than_lying(self):
        """
        A datagram chopped off partway through an answer must raise, so
        that query() can retry over TCP. The failure mode being guarded
        against is returning the records that happened to fit and
        presenting a partial answer as a complete one.

        This is the shape of the bug that made amazon.com and
        mckesson.com fail on the first real scan: the receive buffer was
        the same size as the advertised EDNS buffer, so a response at
        that boundary arrived silently cut short.
        """
        full = build_response([txt_rdata("v=spf1 -all"), txt_rdata("x" * 200)])
        with pytest.raises(DnsError):
            _parse_response(full[:-150], TYPE_TXT)


class TestTxtChunkJoining:
    """
    A TXT record longer than 255 bytes is split into several character
    strings inside one record. They must be concatenated with nothing
    between them. Joining with a space is a common bug that silently
    corrupts long SPF records.
    """

    def test_chunks_are_joined_with_no_separator(self):
        response = DnsResponse(
            name="example.com", qtype=TYPE_TXT, rcode=0,
            records=[txt_rdata("v=spf1 include:_spf.exam", "ple.com -all")],
            truncated=False, used_tcp=False, resolver="test", elapsed_ms=0.0,
        )
        assert response.texts() == ["v=spf1 include:_spf.example.com -all"]

    def test_separate_records_stay_separate(self):
        response = DnsResponse(
            name="example.com", qtype=TYPE_TXT, rcode=0,
            records=[txt_rdata("v=spf1 -all"), txt_rdata("google-site-verification=x")],
            truncated=False, used_tcp=False, resolver="test", elapsed_ms=0.0,
        )
        assert response.texts() == ["v=spf1 -all", "google-site-verification=x"]
