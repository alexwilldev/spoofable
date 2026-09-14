# NC public HBCU email spoofing audit

5 domains assessed. **2 (40%) are spoofable**, meaning forged mail claiming that domain is delivered to the inbox. A further 2 are only partially protected.

| Domain | Verdict | DMARC policy | Why |
| --- | --- | --- | --- |
| ecsu.edu | SPOOFABLE | `p=none` | no DMARC record, so nothing checks the From: header |
| fayettevillestate.edu | SPOOFABLE | `p=none` | no DMARC record, so nothing checks the From: header |
| ncat.edu | WEAK | `p=quarantine` | DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it |
| nccu.edu | WEAK | `p=quarantine` | DMARC p=quarantine delivers forged mail to the spam folder rather than rejecting it |
| wssu.edu | PROTECTED | `p=reject` | DMARC p=reject at 100% with a valid SPF record |
