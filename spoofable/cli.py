"""Command line interface for spoofable."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import List

from .audit import (
    ERROR,
    PROTECTED,
    SPOOFABLE,
    WEAK,
    DomainAudit,
    audit_domain,
    audit_many,
    summarize,
)

# ANSI colours, suppressed when output is piped to a file so that
# redirected output does not fill up with escape sequences.
_COLOURS = {
    SPOOFABLE: "\033[1;31m",  # red
    WEAK: "\033[1;33m",       # yellow
    PROTECTED: "\033[1;32m",  # green
    ERROR: "\033[1;90m",      # grey
}
_RESET = "\033[0m"


def _colour(verdict: str, use_colour: bool) -> str:
    if not use_colour:
        return verdict
    return "%s%s%s" % (_COLOURS.get(verdict, ""), verdict, _RESET)


def _load_targets(path: Path) -> List[str]:
    """
    Read a target list.

    Blank lines and lines starting with # are ignored, so the files in
    data/targets can carry comments explaining where the list came from.
    An inline comment after a domain is also stripped.
    """
    domains = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line:
            domains.append(line)
    return domains


def _print_detail(result: DomainAudit, use_colour: bool) -> None:
    print("%s  %s" % (result.domain, _colour(result.verdict, use_colour)))
    print("  %s" % result.reason)

    if result.dmarc and result.dmarc.raw:
        print("  DMARC: %s" % result.dmarc.raw)
    elif result.dmarc and not result.dmarc.found:
        print("  DMARC: (none published)")

    if result.spf and result.spf.raw:
        print("  SPF:   %s" % result.spf.raw)
        print("  SPF DNS lookups: %d of 10" % result.spf.dns_lookups)
    elif result.spf and not result.spf.found and not result.spf.lookup_failed:
        print("  SPF:   (none published)")

    if result.findings:
        print("  Findings:")
        for finding in result.findings:
            print("    - %s" % finding)


def _write_csv(results: List[DomainAudit], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [r.to_row() for r in results]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _write_markdown(results: List[DomainAudit], path: Path, title: str) -> None:
    stats = summarize(results)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# %s" % title,
        "",
        "%d domains assessed. **%d (%.0f%%) are spoofable**, meaning forged "
        "mail claiming that domain is delivered to the inbox. A further %d "
        "are only partially protected."
        % (
            stats["assessed"],
            stats["spoofable"],
            stats["spoofable_pct"],
            stats["weak"],
        ),
        "",
        "| Domain | Verdict | DMARC policy | Why |",
        "| --- | --- | --- | --- |",
    ]

    order = {SPOOFABLE: 0, WEAK: 1, PROTECTED: 2, ERROR: 3}
    for result in sorted(results, key=lambda r: (order[r.verdict], r.domain)):
        policy = result.dmarc.effective_policy if result.dmarc else "?"
        lines.append(
            "| %s | %s | `p=%s` | %s |"
            % (result.domain, result.verdict, policy, result.reason)
        )

    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def cmd_check(args: argparse.Namespace) -> int:
    result = audit_domain(args.domain)
    if args.json:
        print(json.dumps(result.to_row(), indent=2))
    else:
        _print_detail(result, use_colour=sys.stdout.isatty())
    return 1 if result.spoofable else 0


def cmd_scan(args: argparse.Namespace) -> int:
    if args.targets:
        domains = _load_targets(Path(args.targets))
    else:
        domains = args.domains

    if not domains:
        print("no domains to scan", file=sys.stderr)
        return 2

    use_colour = sys.stdout.isatty()
    print("Scanning %d domains...\n" % len(domains), file=sys.stderr)

    results = audit_many(domains, workers=args.workers)

    width = max(len(d) for d in domains) + 2
    for result in results:
        print(
            "%-*s %s  %s"
            % (width, result.domain, _colour(result.verdict, use_colour), result.reason)
        )

    stats = summarize(results)
    print("")
    print("%d assessed: %d spoofable, %d weak, %d protected, %d errors"
          % (stats["assessed"], stats["spoofable"], stats["weak"],
             stats["protected"], stats["errors"]))
    print("%.0f%% spoofable, %.0f%% not fully enforcing"
          % (stats["spoofable_pct"], stats["not_enforcing_pct"]))

    if args.csv:
        _write_csv(results, Path(args.csv))
        print("\nwrote %s" % args.csv)
    if args.markdown:
        _write_markdown(results, Path(args.markdown), args.title)
        print("wrote %s" % args.markdown)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spoofable",
        description=(
            "Measure whether an organisation can be impersonated over email, "
            "by evaluating its published SPF and DMARC records."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="audit a single domain in detail")
    check.add_argument("domain")
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.set_defaults(func=cmd_check)

    scan = sub.add_parser("scan", help="audit many domains and summarise")
    scan.add_argument("domains", nargs="*", help="domains to scan")
    scan.add_argument("--targets", help="file with one domain per line")
    scan.add_argument("--csv", help="write full results to this CSV path")
    scan.add_argument("--markdown", help="write a report to this Markdown path")
    scan.add_argument("--title", default="Email spoofing audit", help="report title")
    scan.add_argument(
        "--workers", type=int, default=8,
        help="concurrent lookups (default 8; higher risks resolver rate limits)",
    )
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
