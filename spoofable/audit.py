"""
Turning SPF and DMARC records into a single answer to one question:

    Can somebody who is not this organisation send email that appears in
    a recipient's inbox as if it came from this organisation?

WHY DMARC DECIDES THE VERDICT AND SPF DOES NOT

This is the reasoning behind every grade below, and it is the thing to
understand before defending any of this.

SPF validates the envelope sender, the address given in the SMTP
conversation. DKIM validates a cryptographic signature over the message.
Neither of them, on its own, has anything to say about the From: header,
and the From: header is the only sender address a mail client displays.

So an attacker with their own domain can send a message that passes SPF
and passes DKIM for *their* domain, while the From: header reads
president@some-university.edu. Both checks succeed. The recipient sees
the university.

DMARC is the piece that closes this. It requires that the domain which
passed SPF or DKIM must align with the domain in the From: header, and
it tells the receiver what to do when that alignment fails.

Which is why a domain with an immaculate SPF record and no DMARC record
is fully spoofable, and the grading below reflects that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import dmarc as dmarc_mod
from . import spf as spf_mod
from .dmarc import DmarcRecord
from .spf import SpfRecord

# Verdicts, worst first.
SPOOFABLE = "SPOOFABLE"
WEAK = "WEAK"
PROTECTED = "PROTECTED"
ERROR = "ERROR"

VERDICT_ORDER = {SPOOFABLE: 0, WEAK: 1, PROTECTED: 2, ERROR: 3}

VERDICT_SUMMARY = {
    SPOOFABLE: "forged mail is delivered to the inbox",
    WEAK: "forged mail is accepted but filtered, or the policy is partial",
    PROTECTED: "forged mail is rejected",
    ERROR: "could not be assessed",
}


@dataclass
class DomainAudit:
    domain: str
    verdict: str
    reason: str
    spf: Optional[SpfRecord] = None
    dmarc: Optional[DmarcRecord] = None
    findings: List[str] = field(default_factory=list)

    @property
    def spoofable(self) -> bool:
        return self.verdict == SPOOFABLE

    def to_row(self) -> dict:
        """Flat dict for CSV or JSON output."""
        return {
            "domain": self.domain,
            "verdict": self.verdict,
            "reason": self.reason,
            "dmarc_policy": self.dmarc.effective_policy if self.dmarc else "",
            "dmarc_found": bool(self.dmarc and self.dmarc.found),
            "dmarc_pct": self.dmarc.percent if self.dmarc else "",
            "dmarc_subdomain_policy": (
                self.dmarc.subdomain_policy if self.dmarc else ""
            ) or "",
            "dmarc_reporting": bool(self.dmarc and self.dmarc.has_reporting),
            "spf_found": bool(self.spf and self.spf.found),
            "spf_all": (self.spf.all_qualifier if self.spf else "") or "",
            "spf_dns_lookups": self.spf.dns_lookups if self.spf else "",
            "spf_lookup_limit_exceeded": bool(
                self.spf and self.spf.lookup_limit_exceeded
            ),
            "spf_record": (self.spf.raw if self.spf else "") or "",
            "dmarc_record": (self.dmarc.raw if self.dmarc else "") or "",
            "findings": " | ".join(self.findings),
        }


def grade(domain: str, spf: SpfRecord, dmarc: DmarcRecord) -> DomainAudit:
    """Combine the two records into a verdict."""
    findings: List[str] = []
    findings.extend(dmarc.errors)
    findings.extend(dmarc.warnings)
    findings.extend(spf.errors)
    findings.extend(spf.warnings)

    # If we could not reach DNS for the DMARC record, we learned nothing
    # about this domain. Report that honestly instead of grading it.
    #
    # This matters more than it looks. Absence of evidence is not
    # evidence of absence, and a scanner that reports "no DMARC record"
    # when it actually means "my query timed out" produces a confidently
    # wrong security finding. That is the same mistake as ignoring the
    # truncation flag, and it is worth guarding against explicitly.
    if dmarc.lookup_failed:
        return DomainAudit(
            domain, ERROR,
            "DMARC lookup failed, so this domain could not be assessed",
            spf, dmarc, findings,
        )

    # --- SPOOFABLE -------------------------------------------------------
    if not dmarc.found:
        return DomainAudit(
            domain, SPOOFABLE,
            "no DMARC record, so nothing checks the From: header",
            spf, dmarc, findings,
        )

    if dmarc.policy is None:
        return DomainAudit(
            domain, SPOOFABLE,
            "DMARC record is invalid and receivers will discard it",
            spf, dmarc, findings,
        )

    if dmarc.duplicate_records > 1:
        return DomainAudit(
            domain, SPOOFABLE,
            "multiple DMARC records, so receivers ignore all of them",
            spf, dmarc, findings,
        )

    if dmarc.policy == "none":
        return DomainAudit(
            domain, SPOOFABLE,
            "DMARC p=none is monitoring only; forged mail reaches the inbox",
            spf, dmarc, findings,
        )

    if spf.found and spf.all_qualifier == "+":
        return DomainAudit(
            domain, SPOOFABLE,
            "SPF ends in +all, authorising the entire internet to send as "
            "this domain",
            spf, dmarc, findings,
        )

    # --- WEAK ------------------------------------------------------------
    if dmarc.percent < 100:
        return DomainAudit(
            domain, WEAK,
            "DMARC applies to only %d%% of failing mail" % dmarc.percent,
            spf, dmarc, findings,
        )

    if dmarc.policy == "quarantine":
        return DomainAudit(
            domain, WEAK,
            "DMARC p=quarantine delivers forged mail to the spam folder "
            "rather than rejecting it",
            spf, dmarc, findings,
        )

    if dmarc.subdomain_policy == "none":
        return DomainAudit(
            domain, WEAK,
            "apex is protected but sp=none leaves every subdomain open",
            spf, dmarc, findings,
        )

    if spf.lookup_limit_exceeded:
        return DomainAudit(
            domain, WEAK,
            "DMARC enforces, but SPF exceeds the 10 lookup limit and "
            "permanently fails, leaving DKIM as the only path to alignment",
            spf, dmarc, findings,
        )

    if spf.lookup_failed:
        # We reach here only when DMARC enforces at reject and 100%. The
        # remaining question, whether SPF is healthy, is unanswered, and
        # an unanswered question is not a security finding.
        #
        # An earlier version graded this WEAK. That was wrong in a way
        # worth spelling out: WEAK is a claim about the domain, but the
        # only thing that actually went wrong was our own lookup. The
        # symptom was berkshirehathaway.com alternating between
        # PROTECTED and WEAK across runs while nothing at Berkshire
        # changed at all.
        #
        # This is the same principle as the dmarc.lookup_failed guard
        # above, applied consistently: a failed lookup produces ERROR,
        # never a verdict.
        return DomainAudit(
            domain, ERROR,
            "DMARC enforces, but the SPF record could not be retrieved, "
            "so this domain could not be fully assessed",
            spf, dmarc, findings,
        )

    if not spf.found:
        return DomainAudit(
            domain, WEAK,
            "DMARC enforces, but no SPF record means alignment depends "
            "entirely on DKIM",
            spf, dmarc, findings,
        )

    # --- PROTECTED -------------------------------------------------------
    return DomainAudit(
        domain, PROTECTED,
        "DMARC p=reject at 100% with a valid SPF record",
        spf, dmarc, findings,
    )


def audit_domain(domain: str) -> DomainAudit:
    """Run the full audit for one domain."""
    domain = domain.strip().lower().rstrip(".")
    try:
        spf_result = spf_mod.analyze(domain)
        dmarc_result = dmarc_mod.analyze(domain)
        return grade(domain, spf_result, dmarc_result)
    except Exception as exc:  # one bad domain must never kill a scan
        return DomainAudit(
            domain, ERROR, "unexpected error: %s" % exc,
            None, None, ["unexpected error: %r" % exc],
        )


def audit_many(domains, workers: int = 8, on_result=None) -> List[DomainAudit]:
    """
    Audit a list of domains concurrently.

    The worker count is deliberately modest. Each domain costs several
    DNS queries, and public resolvers rate limit; going wide makes the
    scan less reliable, not faster.

    on_result fires the moment each domain finishes, in completion
    order, so a caller can show progress. The returned list is in input
    order regardless, so a run is reproducible and the CSV is stable.

    The distinction matters: an earlier version used pool.map, which
    yields strictly in input order and therefore shows nothing at all
    until the first domain completes. One slow domain made the whole
    scan look like it had hung.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    domains = [d.strip().lower().rstrip(".") for d in domains if d.strip()]
    by_index = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(audit_domain, domain): index
            for index, domain in enumerate(domains)
        }
        for future in as_completed(futures):
            index = futures[future]
            result = future.result()
            by_index[index] = result
            if on_result:
                on_result(result, len(by_index), len(domains))

    return [by_index[i] for i in range(len(domains))]


def summarize(results: List[DomainAudit]) -> dict:
    """Counts by verdict, plus the headline percentage."""
    counts = {SPOOFABLE: 0, WEAK: 0, PROTECTED: 0, ERROR: 0}
    for result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1

    assessed = len(results) - counts[ERROR]
    return {
        "total": len(results),
        "assessed": assessed,
        "spoofable": counts[SPOOFABLE],
        "weak": counts[WEAK],
        "protected": counts[PROTECTED],
        "errors": counts[ERROR],
        "spoofable_pct": (counts[SPOOFABLE] / assessed * 100) if assessed else 0.0,
        "not_enforcing_pct": (
            (counts[SPOOFABLE] + counts[WEAK]) / assessed * 100
        ) if assessed else 0.0,
    }
