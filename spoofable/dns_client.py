"""
A small DNS client, written against the wire format in RFC 1035.

Why not use a library: SPF and DMARC live in TXT records, and getting
TXT records right has exactly one trap in it (truncation, below). Doing
it by hand is about a hundred lines, removes every dependency, and means
the tool has no install step. It also means we control the timeout and
retry behaviour, which matters when scanning a hundred domains.

--------------------------------------------------------------------------
THE TRUNCATION TRAP

A DNS response over UDP has a size limit. Classic DNS caps it at 512
bytes; EDNS0 lets the client advertise a bigger buffer. When the answer
does not fit, the server sends back a response with **no records** and
the TC (truncated) flag set in the header.

A naive client reads "zero answers" and concludes the domain has no SPF
record. That is wrong, and it is wrong specifically for large, important
domains whose TXT records are full of vendor verification strings.
Measured live while building this:

    google.com     TC=1, 0 answers over plain UDP
    microsoft.com  TC=1, 0 answers even with a 4096-byte EDNS buffer
    apple.com      TC=1, 0 answers even with a 4096-byte EDNS buffer
    ncat.edu       TC=1, 0 answers even with a 4096-byte EDNS buffer

Reporting "no SPF record" for those would be a confidently wrong
security finding, which is worse than no finding at all.

The correct behaviour, per RFC 1035 section 4.2.2, is to notice the TC
flag and reissue the query over TCP, where responses are length-prefixed
and can be arbitrarily large. That is what query() does.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

# Record types we use.
TYPE_A = 1
TYPE_TXT = 16
TYPE_MX = 15

CLASS_IN = 1

# Public resolvers, tried in order. Several, because one being slow or
# rate limiting us should not fail a whole scan.
DEFAULT_RESOLVERS: Tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

# Advertised EDNS0 receive buffer. Larger means fewer TCP retries, but
# very large values interact badly with some middleboxes and fragmented
# UDP, so 4096 is the conventional compromise.
EDNS_BUFFER = 4096

DEFAULT_TIMEOUT = 3.0
DEFAULT_ATTEMPTS = 2

# Active settings, overridable from the command line. These are read at
# call time rather than bound as default arguments, so that configure()
# actually takes effect.
#
# The worst case for a single query is timeout x attempts x resolvers.
# With the defaults that is 3 x 2 x 3 = 18 seconds, and evaluating one
# SPF record can issue a dozen queries while walking its includes. On a
# network that silently drops DNS, a single domain can therefore stall
# for minutes. That is worth knowing before raising any of these.
_settings = {
    "resolvers": DEFAULT_RESOLVERS,
    "timeout": DEFAULT_TIMEOUT,
    "attempts": DEFAULT_ATTEMPTS,
}


def configure(resolvers=None, timeout=None, attempts=None) -> None:
    """Override the resolver list, per-query timeout, or retry count."""
    if resolvers:
        _settings["resolvers"] = tuple(resolvers)
    if timeout is not None:
        _settings["timeout"] = float(timeout)
    if attempts is not None:
        _settings["attempts"] = int(attempts)

# Rcodes we care about distinguishing (RFC 1035 section 4.1.1).
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsError(Exception):
    """Raised when a query could not be answered by any resolver."""


@dataclass(frozen=True)
class DnsResponse:
    """A decoded DNS response."""

    name: str
    qtype: int
    rcode: int
    records: List[bytes]
    truncated: bool
    used_tcp: bool
    resolver: str
    elapsed_ms: float

    @property
    def rcode_name(self) -> str:
        return _RCODE_NAMES.get(self.rcode, "RCODE%d" % self.rcode)

    @property
    def ok(self) -> bool:
        return self.rcode == RCODE_NOERROR

    @property
    def nxdomain(self) -> bool:
        return self.rcode == RCODE_NXDOMAIN

    def texts(self) -> List[str]:
        """TXT record values, decoded to str.

        A TXT record is a sequence of length-prefixed strings, each at
        most 255 bytes. A long SPF record is therefore split into several
        chunks inside a single record, and the chunks are concatenated
        with no separator. Joining them with a space, which is an easy
        mistake, corrupts the record.
        """
        out = []
        for raw in self.records:
            chunks = []
            i = 0
            while i < len(raw):
                length = raw[i]
                chunks.append(raw[i + 1 : i + 1 + length])
                i += 1 + length
            out.append(b"".join(chunks).decode("utf-8", errors="replace"))
        return out


def encode_name(name: str) -> bytes:
    """
    Encode a domain name in DNS wire format: each label prefixed by its
    length, terminated by a zero byte. "a.example.com" becomes
    \\x01a\\x07example\\x03com\\x00
    """
    name = name.rstrip(".")
    if not name:
        return b"\x00"

    out = bytearray()
    for label in name.split("."):
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not 1 <= len(encoded) <= 63:
            raise ValueError("label %r must be 1..63 bytes" % label)
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def _skip_name(data: bytes, offset: int) -> int:
    """
    Walk past a name in the packet and return the offset just after it.

    Names can be compressed: a label whose top two bits are set is a
    pointer to an earlier offset, and a pointer always ends the name. We
    only need to skip names, not read them, so we never follow pointers,
    which conveniently makes pointer loops impossible here.
    """
    while True:
        if offset >= len(data):
            raise DnsError("packet truncated while reading a name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2  # two-byte pointer, and the name ends here
        offset += 1 + length


def _parse_response(data: bytes, want_type: int) -> Tuple[int, bool, List[bytes]]:
    """Return (rcode, truncated, [record data]) for matching answers."""
    if len(data) < 12:
        raise DnsError("response shorter than a DNS header")

    _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    truncated = bool((flags >> 9) & 1)

    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        offset += 4  # qtype + qclass

    records: List[bytes] = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)

        # Every answer the header promised must actually be present. If
        # the buffer ends early we must say so, not quietly return the
        # records that happened to fit: a partial answer returned as a
        # complete one is how a domain with a perfectly good SPF record
        # gets reported as having none.
        if offset + 10 > len(data):
            raise DnsError(
                "response ended before the answer section was complete "
                "(header promised %d answers)" % ancount
            )

        rtype, _rclass, _ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10

        if offset + rdlength > len(data):
            raise DnsError("record data runs past the end of the response")

        rdata = data[offset : offset + rdlength]
        offset += rdlength

        # CNAMEs and other types can appear in the answer section; keep
        # only the type we asked about.
        if rtype == want_type:
            records.append(rdata)

    return rcode, truncated, records


def _build_query(name: str, qtype: int, use_edns: bool = True) -> bytes:
    """Assemble a standard recursive query."""
    # Random transaction ID. It is a weak defence against off-path
    # spoofing, but leaving it constant is worse for no benefit.
    tid = random.getrandbits(16)
    flags = 0x0100  # RD (recursion desired)
    arcount = 1 if use_edns else 0

    packet = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, arcount)
    packet += encode_name(name)
    packet += struct.pack("!HH", qtype, CLASS_IN)

    if use_edns:
        # An OPT pseudo-record: root name, type 41, and the class field
        # repurposed to advertise our receive buffer size.
        packet += b"\x00" + struct.pack("!HHIH", 41, EDNS_BUFFER, 0, 0)

    return packet


def _query_udp(packet: bytes, resolver: str, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (resolver, 53))
        # Read with a buffer larger than the one we advertised. recvfrom
        # silently discards anything past the size requested, so reading
        # exactly EDNS_BUFFER bytes means a datagram of exactly that size
        # arrives looking complete but cut off mid-record, and the parser
        # then walks off the end of a name.
        #
        # This is not hypothetical. It is what made amazon.com and
        # mckesson.com fail with "packet truncated while reading a name"
        # on the first real scan: their TXT responses are large enough to
        # hit the boundary.
        return sock.recvfrom(65535)[0]
    finally:
        sock.close()


def _query_tcp(packet: bytes, resolver: str, timeout: float) -> bytes:
    """
    Reissue over TCP. DNS over TCP frames each message with a two-byte
    big-endian length prefix, and a read can return fewer bytes than
    asked for, so both the prefix and the body are read in a loop.
    """
    sock = socket.create_connection((resolver, 53), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!H", len(packet)) + packet)

        header = _recv_exactly(sock, 2)
        (length,) = struct.unpack("!H", header)
        return _recv_exactly(sock, length)
    finally:
        sock.close()


def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise DnsError("connection closed mid-response")
        buf += chunk
    return bytes(buf)


def query(
    name: str,
    qtype: int = TYPE_TXT,
    resolvers: Optional[Sequence[str]] = None,
    timeout: Optional[float] = None,
    attempts: Optional[int] = None,
) -> DnsResponse:
    """
    Resolve name/qtype, retrying across resolvers and falling back to TCP
    when the answer is truncated.

    Raises DnsError only when every resolver failed to answer at all. A
    negative answer such as NXDOMAIN is a successful query with a
    non-zero rcode, not an exception, because "this domain publishes no
    DMARC record" is a finding rather than an error.
    """
    resolvers = tuple(resolvers) if resolvers else _settings["resolvers"]
    timeout = _settings["timeout"] if timeout is None else timeout
    attempts = _settings["attempts"] if attempts is None else attempts

    packet = _build_query(name, qtype)
    started = time.perf_counter()
    last_error: Optional[Exception] = None

    for attempt in range(attempts):
        for resolver in resolvers:
            try:
                raw = _query_udp(packet, resolver, timeout)
                try:
                    rcode, truncated, records = _parse_response(raw, qtype)
                except DnsError:
                    # The datagram did not parse. Rather than moving to
                    # the next resolver, which will almost certainly
                    # return the same oversized answer, retry this one
                    # over TCP where the response is length-prefixed and
                    # cannot be cut short.
                    truncated = True
                    rcode, records = RCODE_NOERROR, []

                if truncated:
                    # The answer exists but did not fit. This is the
                    # case that silently breaks naive implementations.
                    raw = _query_tcp(packet, resolver, timeout)
                    rcode, truncated, records = _parse_response(raw, qtype)
                    return DnsResponse(
                        name=name, qtype=qtype, rcode=rcode, records=records,
                        truncated=True, used_tcp=True, resolver=resolver,
                        elapsed_ms=(time.perf_counter() - started) * 1000,
                    )

                return DnsResponse(
                    name=name, qtype=qtype, rcode=rcode, records=records,
                    truncated=False, used_tcp=False, resolver=resolver,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )

            except (socket.timeout, OSError, DnsError) as exc:
                last_error = exc
                continue

        # Back off a little before the next sweep, so that a resolver
        # rate limiting us gets a chance to forgive.
        if attempt + 1 < attempts:
            time.sleep(0.3 * (attempt + 1))

    raise DnsError("no resolver answered for %s (%s)" % (name, last_error))


def query_txt(name: str, **kwargs) -> List[str]:
    """Convenience wrapper: return TXT strings, or [] for a negative answer."""
    response = query(name, TYPE_TXT, **kwargs)
    if not response.ok:
        return []
    return response.texts()
