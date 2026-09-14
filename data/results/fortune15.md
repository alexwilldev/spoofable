# Fortune 15 email spoofing audit

15 domains assessed. **1 (7%) are spoofable**, meaning forged mail claiming that domain is delivered to the inbox. A further 6 are only partially protected.

| Domain | Verdict | DMARC policy | Why |
| --- | --- | --- | --- |
| chevron.com | SPOOFABLE | `p=none` | DMARC p=none is monitoring only; forged mail reaches the inbox |
| alphabet.com | WEAK | `p=quarantine` | DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it |
| amazon.com | WEAK | `p=quarantine` | DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it |
| apple.com | WEAK | `p=quarantine` | DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it |
| mckesson.com | WEAK | `p=reject` | DMARC p=reject, but the SPF record could not be retrieved, so the SPF half is unverified |
| microsoft.com | WEAK | `p=reject` | DMARC p=reject, but the SPF record could not be retrieved, so the SPF half is unverified |
| unitedhealthgroup.com | WEAK | `p=reject` | apex is protected but sp=none leaves every subdomain open |
| berkshirehathaway.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| cardinalhealth.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| cencora.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| costco.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| cvshealth.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| exxonmobil.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| jpmorganchase.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
| walmart.com | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
