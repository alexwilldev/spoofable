# spoofable

[![tests](https://github.com/alexwilldev/spoofable/actions/workflows/tests.yml/badge.svg)](https://github.com/alexwilldev/spoofable/actions/workflows/tests.yml)

Measures whether an organization can be impersonated over email, by evaluating the SPF and DMARC records it publishes in DNS.

No dependencies. Python standard library only, including the DNS client.

```
$ spoofable scan --targets data/targets/nc-public-hbcu.txt

ncat.edu                WEAK        DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it
nccu.edu                WEAK        DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it
ecsu.edu                SPOOFABLE   DMARC p=none is monitoring only; forged mail reaches the inbox
fayettevillestate.edu   SPOOFABLE   no DMARC record, so nothing checks the From: header
wssu.edu                PROTECTED   DMARC p=reject at 100% with a valid SPF record

5 assessed: 2 spoofable, 2 weak, 1 protected, 0 errors
40% spoofable, 80% not fully enforcing
```

## The question this answers

> Can somebody who is not this organization send email that lands in a recipient's inbox appearing to come from this organization?

## Why SPF alone does not answer it

This is the reasoning the whole tool is built on.

**SPF** validates the *envelope sender*, the address given during the SMTP conversation. **DKIM** validates a cryptographic signature over the message. Neither has anything to say about the `From:` header.

The `From:` header is the only sender address a mail client displays.

So an attacker sending from a domain they own can pass SPF and pass DKIM for *their* domain, while the `From:` header reads `president@some-university.edu`. Every check succeeds. The recipient sees the university.

**DMARC** is what closes this. It requires that the domain which passed SPF or DKIM *align* with the domain in the `From:` header, and it tells receivers what to do when alignment fails.

Which is why a domain with an immaculate SPF record and no DMARC record is fully spoofable, and why the verdict below is driven by DMARC.

## Verdicts

| Verdict | Meaning | Triggered by |
| --- | --- | --- |
| `SPOOFABLE` | Forged mail is delivered to the inbox | No DMARC record, `p=none`, an invalid or duplicated DMARC record, or SPF ending in `+all` |
| `WEAK` | Forged mail is accepted but filtered, or the policy is partial | `p=quarantine`, `pct<100`, `sp=none`, or an enforcing DMARC with SPF missing or broken |
| `PROTECTED` | Forged mail is rejected | `p=reject` at 100% with a valid SPF record |
| `ERROR` | Could not be assessed | DNS lookups failed. **Never** reported as a finding |

## Install

Nothing to install. Python 3.9 or newer.

```bash
git clone https://github.com/alexwilldev/spoofable.git
cd spoofable
python3 -m spoofable check ncat.edu
```

Optionally, to get a `spoofable` command on your PATH:

```bash
pip install -e .
```

## Usage

Audit one domain in detail:

```bash
$ spoofable check ncat.edu

ncat.edu  WEAK
  DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it
  DMARC: v=DMARC1; p=quarantine; rua=mailto:hostmaster@ncat.edu
  SPF:   v=spf1 include:spf.protection.outlook.com -all
  SPF DNS lookups: 2 of 10
```

Scan a list and write out the data:

```bash
spoofable scan --targets data/targets/fortune15.txt \
  --csv out/fortune15.csv \
  --markdown out/fortune15.md \
  --title "Fortune 15 email spoofing audit"
```

Machine-readable single result:

```bash
spoofable check ncat.edu --json
```

`check` exits `1` when the domain is spoofable and `0` otherwise, so it drops into a CI pipeline or a cron job without extra glue.

## Two correctness problems worth knowing about

Both of these produce *confidently wrong security findings*, which are worse than no findings. Both are handled, and both are covered by tests.

### 1. Truncated DNS responses look identical to "no record"

A DNS response over UDP has a size limit. When the answer does not fit, the server returns a response with **zero records** and the `TC` (truncated) flag set.

A client that ignores that flag reads "zero answers" and reports *no SPF record*. Measured live against real domains, all of these truncate:

```
google.com     microsoft.com     apple.com     ncat.edu     walmart.com
```

Reporting "no SPF record" for Apple and Microsoft would be nonsense. [RFC 1035 §4.2.2](https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2) says to reissue the query over TCP, which is what `dns_client.query()` does.

### 2. "I could not ask" is not "there is no record"

An early version of this tool reported `cisco.com` and `wellsfargo.com` as having **no SPF record**. They both have one. The queries had timed out, and the code treated a network failure as an absence.

`SpfRecord.lookup_failed` and `DmarcRecord.lookup_failed` are now tracked separately from `found`, and a failed lookup produces `ERROR` or an explicitly unverified result, never a finding.

## How SPF's 10-lookup limit is handled

SPF permits at most **10 DNS lookups** across an entire evaluation, counting every `include`, `a`, `mx`, `ptr`, `exists`, and `redirect`. Exceed it and receivers must return `PermError`, meaning the record fails permanently for everyone.

Organizations accumulate vendor `include`s over the years and cross the line without noticing, so the record they believe protects them does nothing at all.

Counting this correctly requires walking the include tree rather than counting terms in the top-level record, which is what `spf.count_lookups()` does, with loop detection for records that include themselves.

## Is this legal?

Yes, and it is worth being precise about why. The tool reads **public DNS records**, the same records every mail server on the internet reads before accepting a message. It does not connect to any of the organization's systems, send mail, scan ports, or authenticate to anything. It is passive reconnaissance of published data.

## Limitations

- **DKIM is not evaluated.** DKIM keys live at a selector-specific name (`selector._domainkey.example.com`) and selectors are not discoverable from outside, so an external audit cannot enumerate them. The verdict accounts for this by treating DMARC alignment as the deciding factor.
- **A `PROTECTED` verdict means the published policy is correct**, not that the organization is impossible to phish. Lookalike domains, display-name spoofing, and compromised accounts all bypass DMARC entirely.
- **Results are a snapshot.** DNS changes. Every dataset in `data/` is timestamped.
- **Subdomain coverage is inferred** from the `sp=` tag rather than enumerated.

## Layout

```
spoofable/
  dns_client.py   DNS over UDP with TCP fallback, written against RFC 1035
  spf.py          SPF parsing, qualifier extraction, recursive lookup counting
  dmarc.py        DMARC tag parsing and policy evaluation
  audit.py        Combines both into a verdict
  cli.py          Command line interface
data/targets/     Domain lists, with sources noted
tests/            67 tests, all offline
```

## Tests

```bash
python3 -m pytest
```

The suite runs entirely against packets and records constructed in the tests, so it passes with the network disconnected.

## License

MIT
