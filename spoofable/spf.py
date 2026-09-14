"""
SPF: parsing and evaluating Sender Policy Framework records (RFC 7208).

SPF is a TXT record at the domain apex listing which servers may send
mail for the domain, ending in an "all" mechanism that says what to do
with everyone else.

    v=spf1 include:_spf.google.com ~all

Three things about SPF matter for this audit, and the third is the one
people get wrong.

1. THE FINAL QUALIFIER IS THE POLICY.
   -all  hard fail    "nobody else, reject them"
   ~all  soft fail    "nobody else, but accept it anyway and flag it"
   ?all  neutral      "no opinion", which is the same as having no policy
   +all  pass         "anyone on the internet may send as us". Always a
                      misconfiguration, and a total failure of the record.

2. THERE IS A HARD LIMIT OF 10 DNS LOOKUPS.
   Every include, a, mx, ptr, exists, and redirect costs a lookup, and
   the budget is shared across the whole recursive evaluation, not per
   record. Exceed it and a receiver must return PermError, which means
   the record fails permanently for everyone. Organisations stack up
   vendor includes over the years and cross the line without noticing,
   so the record they think protects them does nothing. Counting this
   correctly requires actually walking the include tree, which is what
   count_lookups() below does.

3. SPF DOES NOT CHECK THE ADDRESS THE HUMAN SEES.
   SPF validates the envelope sender (the MAIL FROM in the SMTP
   conversation). Your mail client does not display that. It displays
   the From: header, which is a completely separate field that SPF never
   looks at. So an attacker can pass SPF for a domain they legitimately
   control while putting anything they like in the From: header.

   This is why a perfect SPF record alone does not stop impersonation,
   and why the verdict in audit.py is driven by DMARC rather than SPF.
   DMARC is the piece that requires the two to match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Set

from .dns_client import DnsError, query_txt

SPF_VERSION = "v=spf1"

# Mechanisms and modifiers that each consume one of the 10 DNS lookups.
LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
MAX_DNS_LOOKUPS = 10

QUALIFIER_MEANING = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}


@dataclass
class SpfRecord:
    domain: str
    raw: Optional[str] = None
    found: bool = False
    # True when we could not get an answer at all. This is deliberately
    # separate from found=False, which means "we asked, and there is no
    # record". Collapsing the two lets a network failure masquerade as a
    # security finding, which is the same class of mistake as ignoring
    # the truncation flag in dns_client.
    lookup_failed: bool = False
    # More than one v=spf1 record is a permanent error under the spec:
    # a receiver cannot choose between them, so it must reject both.
    duplicate_records: int = 0
    all_qualifier: Optional[str] = None
    has_redirect: bool = False
    dns_lookups: int = 0
    lookup_limit_exceeded: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def all_meaning(self) -> Optional[str]:
        if self.all_qualifier is None:
            return None
        return QUALIFIER_MEANING.get(self.all_qualifier)

    @property
    def is_permerror(self) -> bool:
        """True when a receiver would be forced to treat SPF as broken."""
        return bool(self.errors) or self.lookup_limit_exceeded or self.duplicate_records > 1


def find_spf_record(txt_values: List[str]) -> List[str]:
    """
    Pick the SPF records out of a domain's TXT records.

    A domain's TXT records are a junk drawer of vendor verification
    strings, so we match on the required v=spf1 prefix. The comparison is
    case insensitive because the version token is case insensitive, and
    real records in the wild do use V=spf1.
    """
    return [
        value.strip()
        for value in txt_values
        if value.strip().lower().startswith(SPF_VERSION)
    ]


def _split_terms(record: str) -> List[str]:
    """Split an SPF record into its terms, dropping the version token."""
    return record.split()[1:]


def parse_all_qualifier(record: str) -> Optional[str]:
    """
    Return the qualifier on the 'all' mechanism, or None if absent.

    A bare 'all' with no qualifier means '+all', because + is the default
    qualifier in SPF. That default is a genuine trap: a record ending in
    a bare 'all' authorises the entire internet.
    """
    for term in _split_terms(record):
        bare = term[1:] if term[:1] in QUALIFIER_MEANING else term
        if bare.lower() == "all":
            return term[:1] if term[:1] in QUALIFIER_MEANING else "+"
    return None


def count_lookups(
    domain: str,
    record: str,
    _seen: Optional[Set[str]] = None,
    _depth: int = 0,
) -> int:
    """
    Count the DNS lookups a receiver would spend evaluating this record,
    following include and redirect the way a real evaluator does.

    _seen guards against include loops, which exist in the wild and would
    otherwise recurse forever. _depth is a second belt-and-braces bound.

    A lookup that fails to resolve still counts against the budget, so
    unresolvable includes are counted rather than skipped.
    """
    if _seen is None:
        _seen = set()
    if _depth > MAX_DNS_LOOKUPS + 2:
        return MAX_DNS_LOOKUPS + 1

    total = 0
    for term in _split_terms(record):
        bare = term[1:] if term[:1] in QUALIFIER_MEANING else term
        lowered = bare.lower()

        name = None
        if lowered.startswith("include:"):
            name = bare[len("include:") :]
        elif lowered.startswith("redirect="):
            name = bare[len("redirect=") :]
        elif lowered == "a" or lowered.startswith(("a:", "a/")):
            total += 1
            continue
        elif lowered == "mx" or lowered.startswith(("mx:", "mx/")):
            total += 1
            continue
        elif lowered == "ptr" or lowered.startswith("ptr:"):
            total += 1
            continue
        elif lowered.startswith("exists:"):
            total += 1
            continue
        else:
            continue

        total += 1
        if not name or name.lower() in _seen:
            continue
        _seen.add(name.lower())

        # Already over budget; no point spending more real queries.
        if total > MAX_DNS_LOOKUPS:
            continue

        try:
            nested = find_spf_record(query_txt(name))
        except DnsError:
            continue
        if nested:
            total += count_lookups(name, nested[0], _seen, _depth + 1)

    return total


def analyze(domain: str, txt_values: Optional[List[str]] = None) -> SpfRecord:
    """Fetch (if needed) and evaluate the SPF record for a domain."""
    result = SpfRecord(domain=domain)

    if txt_values is None:
        try:
            txt_values = query_txt(domain)
        except DnsError as exc:
            result.lookup_failed = True
            result.errors.append("DNS lookup failed: %s" % exc)
            return result

    records = find_spf_record(txt_values)
    result.duplicate_records = len(records)

    if not records:
        result.warnings.append("no SPF record published")
        return result

    if len(records) > 1:
        result.errors.append(
            "%d SPF records published; the spec requires exactly one, "
            "so receivers must treat this as a permanent error" % len(records)
        )

    record = records[0]
    result.found = True
    result.raw = record

    result.all_qualifier = parse_all_qualifier(record)
    result.has_redirect = any(
        term.lower().startswith("redirect=") for term in _split_terms(record)
    )

    if result.all_qualifier is None and not result.has_redirect:
        result.warnings.append(
            "record has neither an 'all' mechanism nor a redirect, "
            "so unlisted senders get no verdict"
        )
    elif result.all_qualifier == "+":
        result.errors.append(
            "record ends in +all, which authorises every host on the "
            "internet to send mail as this domain"
        )

    try:
        result.dns_lookups = count_lookups(domain, record)
    except Exception as exc:  # never let one domain kill a scan
        result.warnings.append("could not count DNS lookups: %s" % exc)
        result.dns_lookups = 0

    if result.dns_lookups > MAX_DNS_LOOKUPS:
        result.lookup_limit_exceeded = True
        result.errors.append(
            "record needs %d DNS lookups, over the limit of %d; receivers "
            "must return PermError, so this record silently protects nothing"
            % (result.dns_lookups, MAX_DNS_LOOKUPS)
        )
    elif result.dns_lookups >= MAX_DNS_LOOKUPS - 1:
        result.warnings.append(
            "record uses %d of %d permitted DNS lookups; adding one more "
            "vendor will break it" % (result.dns_lookups, MAX_DNS_LOOKUPS)
        )

    return result
