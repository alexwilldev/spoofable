"""
DMARC: parsing and evaluating DMARC records (RFC 7489).

DMARC is the record that makes SPF and DKIM actually protect the address
a human sees. It does two things:

  ALIGNMENT. It requires that the domain SPF or DKIM validated matches
  the domain in the From: header. Without this, an attacker can pass SPF
  for a domain they own while showing your domain in the From: line.

  POLICY. It tells receivers what to do when that check fails, via the
  p= tag:

      p=reject      refuse the message outright
      p=quarantine  accept it, but put it in the spam folder
      p=none        accept it and deliver it normally

p=none is the part worth dwelling on. It is "monitoring mode", meant as
a temporary step while an organisation finds its legitimate senders.
It provides no protection at all: forged mail is delivered to the inbox
exactly as if there were no DMARC record. A great many organisations
publish p=none, see a valid record in their dashboard, and believe they
are finished. They are not, and this audit exists to say so.

Two more tags change how much a policy is worth:

  pct=  applies the policy to only that percentage of failing mail.
        pct=10 with p=reject means nine out of ten forgeries still land.
  sp=   sets a different policy for subdomains. An organisation with
        p=reject and sp=none is wide open on every subdomain, and
        attackers do look for that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .dns_client import DnsError, query_txt

DMARC_PREFIX = "_dmarc."
DMARC_VERSION = "v=dmarc1"

VALID_POLICIES = ("none", "quarantine", "reject")


@dataclass
class DmarcRecord:
    domain: str
    raw: Optional[str] = None
    found: bool = False
    # See the note on SpfRecord.lookup_failed: "we could not ask" and
    # "there is no record" are different answers and must not be merged.
    lookup_failed: bool = False
    duplicate_records: int = 0
    policy: Optional[str] = None
    subdomain_policy: Optional[str] = None
    percent: int = 100
    rua: List[str] = field(default_factory=list)
    ruf: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def effective_policy(self) -> str:
        """The policy a receiver would actually apply to the apex domain."""
        if not self.found or self.policy is None:
            return "none"
        return self.policy

    @property
    def enforced(self) -> bool:
        """True when failing mail is actually acted on."""
        return self.effective_policy in ("quarantine", "reject")

    @property
    def has_reporting(self) -> bool:
        return bool(self.rua)


def parse_tags(record: str) -> Dict[str, str]:
    """
    Split a DMARC record into its tag=value pairs.

    Tags are separated by semicolons, whitespace around them is
    insignificant, and a trailing semicolon is permitted. Tag names are
    case insensitive; values mostly are too, so both are lowercased
    except for the reporting addresses, which are kept verbatim.
    """
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key not in ("rua", "ruf"):
            value = value.lower()
        tags[key] = value
    return tags


def _parse_addresses(value: str) -> List[str]:
    """Parse a rua/ruf value into a list of destinations."""
    out = []
    for item in value.split(","):
        item = item.strip()
        if item.lower().startswith("mailto:"):
            item = item[len("mailto:") :]
        # A destination may carry a size limit suffix, e.g. !10m
        item = item.split("!")[0]
        if item:
            out.append(item)
    return out


def analyze(domain: str, txt_values: Optional[List[str]] = None) -> DmarcRecord:
    """Fetch (if needed) and evaluate the DMARC record for a domain."""
    result = DmarcRecord(domain=domain)
    lookup_name = DMARC_PREFIX + domain.rstrip(".")

    if txt_values is None:
        try:
            txt_values = query_txt(lookup_name)
        except DnsError as exc:
            result.lookup_failed = True
            result.errors.append("DNS lookup failed: %s" % exc)
            return result

    records = [
        value.strip()
        for value in txt_values
        if value.strip().lower().startswith(DMARC_VERSION)
    ]
    result.duplicate_records = len(records)

    if not records:
        result.warnings.append(
            "no DMARC record published, so forged mail claiming this "
            "domain is delivered normally"
        )
        return result

    if len(records) > 1:
        result.errors.append(
            "%d DMARC records published; receivers must ignore all of "
            "them, leaving the domain unprotected" % len(records)
        )

    record = records[0]
    result.found = True
    result.raw = record
    result.tags = parse_tags(record)

    policy = result.tags.get("p")
    if policy is None:
        result.errors.append(
            "record has no p= tag, which is required; receivers will "
            "discard the record"
        )
    elif policy not in VALID_POLICIES:
        result.errors.append("invalid policy p=%s" % policy)
    else:
        result.policy = policy
        if policy == "none":
            result.warnings.append(
                "p=none is monitoring only and provides no protection; "
                "forged mail still reaches the inbox"
            )

    subdomain_policy = result.tags.get("sp")
    if subdomain_policy in VALID_POLICIES:
        result.subdomain_policy = subdomain_policy
        if result.policy in ("reject", "quarantine") and subdomain_policy == "none":
            result.warnings.append(
                "sp=none leaves every subdomain unprotected even though "
                "the apex policy is %s" % result.policy
            )

    raw_pct = result.tags.get("pct")
    if raw_pct is not None:
        try:
            percent = int(raw_pct)
        except ValueError:
            result.warnings.append("pct=%s is not a number; treating as 100" % raw_pct)
        else:
            if 0 <= percent <= 100:
                result.percent = percent
                if percent < 100 and result.policy in ("reject", "quarantine"):
                    result.warnings.append(
                        "pct=%d applies the policy to only %d%% of failing "
                        "mail; the rest is delivered" % (percent, percent)
                    )
            else:
                result.warnings.append("pct=%d is out of range 0..100" % percent)

    if "rua" in result.tags:
        result.rua = _parse_addresses(result.tags["rua"])
    if "ruf" in result.tags:
        result.ruf = _parse_addresses(result.tags["ruf"])

    if not result.rua:
        result.warnings.append(
            "no rua= address, so nobody receives aggregate reports and "
            "abuse of the domain goes unseen"
        )

    return result
