# Sanitization ruleset (private source -> public)

This public repo is the sanitized, adaptable version of an internal integration built
against a live environment. **Nothing here may contain a real environment fact.**

## The rule

Treat any accidental leak as a **rotation event** (rotate the exposed credential), not
merely a git-history rewrite.

## Placeholder conventions

| Real thing | Public placeholder |
|------------|--------------------|
| WAF host / API base | `<WAF_HOST>` / `https://<WAF_HOST>:8443` |
| Graylog host | `<GRAYLOG_HOST>` |
| Wazuh manager | `<WAZUH_HOST>` |
| Wazuh indexer | `<WAZUH_INDEXER>` |
| Internal backend host | `<INTERNAL_HOST>` |
| Service-account email/pass | from env (`WAF_ADMIN_EMAIL` / `WAF_ADMIN_PASSWORD`), never literal |
| WAF API key | never literal; env only |
| Example networks | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC5737 TEST-NET) |
| Example published site | `site.example.com` |
| Example domain | `example.com` / `example.local` |
| Real attacker IPs / geo in samples | synthetic values in `samples/`, clearly labelled SYNTHETIC |

## Forbidden in public (enforced by scrub-check)

- `secdoc.home`, `secdoc.tech`, real published hostnames
- Any real `10.10.10.x`, `192.168.x.x`, `10.13.37.x` address
- Real VM ids, cron job ids, cluster/zone names
- Any credential, token, or `waf_...` key fragment

## The gate

Before **every** public commit:

```bash
python3 scripts/scrub_check.py .
```

Exit 0 = safe to publish. Non-zero = it found a leak; fix it first. Extend the
`FORBIDDEN` list in `scripts/scrub_check.py` as needed. The scrub-check is a safety
net, not a substitute for reviewing the diff by hand.
