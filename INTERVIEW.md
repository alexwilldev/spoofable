# Technical Interview: spoofable

**Project:** spoofable, an SPF and DMARC email spoofing auditor
**Candidate:** Alex Williams
**Course:** COMP163, NC A&T, Fall 2026
**Date:** September 14, 2026

Questions asked by Claude (Opus 5). Answers written by me, in my own words.

---

## The project

### 1. Walk me through this project. What does it do, and why did you build it?

**Answer:**



---

### 2. Explain SPF to someone who has never heard of it.

**Answer:**



---

### 3. Explain DMARC to someone who has never heard of it.

**Answer:**



---

## The reasoning

### 4. A domain publishes a flawless SPF record, locked down, ending in `-all`, no mistakes anywhere. It publishes no DMARC record. Your tool labels it `SPOOFABLE`. Defend that. Isn't SPF the thing that's supposed to stop spoofing?

**Answer:**



---

### 5. What is the practical difference between `p=none`, `p=quarantine` and `p=reject` for a forged message?

**Answer:**



---

### 6. An organization's security dashboard shows their DMARC record as valid and correctly formatted. Can I still forge email from them? What would you need to look at to know for sure?

**Answer:**



---

### 7. Why does your tool not check DKIM?

**Answer:**



---

## Design and correctness

### 8. Why did you write your own DNS client instead of using a library? What is the downside of that choice?

**Answer:**



---

### 9. What is the TC flag, and why does your code care about it?

**Answer:**



---

### 10. Why does a truncated response require retrying over TCP, rather than just asking again over UDP?

**Answer:**



---

### 11. In your code, what is the difference between "this domain has no SPF record" and "I could not retrieve this domain's SPF record"? Why does that distinction exist?

**Answer:**



---

### 12. What happens if I point your tool at a domain that does not exist? What about a domain whose nameservers are unreachable? Should those produce the same output?

**Answer:**



---

### 13. What is the 10-lookup limit in SPF, and why can you not count those lookups by reading the record alone?

**Answer:**



---

## The data

### 14. Your results show 40% of NC public HBCUs spoofable versus 7% of the Fortune 15. What do you conclude from that? What can you not conclude from it?

**Answer:**



---

### 15. Your sample is five schools and fifteen companies. Is that enough to support the claim you are making?

**Answer:**



---

## Legality and reflection

### 16. Is what this tool does legal? How is it different from port scanning those same organizations?

**Answer:**



---

### 17. What is the weakest part of this project, and what would you change?

**Answer:**



---
