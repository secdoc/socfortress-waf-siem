#!/usr/bin/env python3
"""Scrub-check gate: scan a directory tree for environment-specific facts that
must NEVER appear in this PUBLIC repo. Exit non-zero if any are found.

Run before every public commit:  python3 scripts/scrub_check.py <dir>
Default dir = current directory.
"""
import sys, os, re

# Patterns that indicate real environment leakage. Extend as the estate grows.
FORBIDDEN = [
    (r"\bsecdoc\.home\b",                     "internal domain secdoc.home"),
    (r"\bsecdoc\.tech\b",                      "real domain secdoc.tech"),
    (r"search\.secdoc",                        "real published site hostname"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b",       "real RFC1918 192.168.x.x address"),
    (r"\b10\.10\.10\.\d{1,3}\b",              "real DMZ 10.10.10.x address"),
    (r"\b10\.13\.37\.\d{1,3}\b",              "ESSEXLAB 10.13.37.x address"),
    (r"\bVM\s?129\b",                          "real VM id"),
    (r"\bESSEXLAB\b",                          "internal lab/zone name"),
    (r"\bpvecluster\b",                        "real Proxmox cluster name"),
    (r"\b5217ce18fb7a\b",                      "real cron job id"),
    (r"(?i)\bwaf_[A-Za-z0-9]{20,}",           "WAF API key fragment"),
    (r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*_\-]{8,}",
     "possible hardcoded secret value"),
]
# Values that ARE allowed (documentation placeholders / example ranges)
ALLOW = [
    r"192\.0\.2\.",     # TEST-NET-1 (RFC5737)
    r"198\.51\.100\.",  # TEST-NET-2
    r"203\.0\.113\.",   # TEST-NET-3
    r"<[A-Z_]+>",       # <WAF_HOST> style placeholders
    r"example\.(com|org|net|local)",
]
# Lines that legitimately contain an otherwise-forbidden token. The author's
# required license attribution string ("... secdoc.tech") appears verbatim in
# NOTICE/LICENSING per CC BY 4.0 and is intentional, not an environment leak.
ALLOW_LINES = [
    r"Lester E\. Nichols III, secdoc\.tech",
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
# Files that legitimately CONTAIN the forbidden patterns because they DEFINE them.
SKIP_FILES = {"scrub_check.py", "SANITIZATION.md"}


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if fn in SKIP_FILES:
                continue
            p = os.path.join(dp, fn)
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    for n, line in enumerate(f, 1):
                        if any(re.search(a, line) for a in ALLOW_LINES):
                            continue
                        for pat, desc in FORBIDDEN:
                            for m in re.finditer(pat, line):
                                matched = m.group(0)
                                if any(re.fullmatch(a, matched) or re.search(a, matched) for a in ALLOW):
                                    continue
                                hits.append((p, n, desc, line.strip()[:120]))
            except Exception:
                continue
    if hits:
        print(f"SCRUB-CHECK FAILED: {len(hits)} environment leak(s) found\n")
        for p, n, desc, txt in hits:
            print(f"  {p}:{n}  [{desc}]\n      {txt}")
        print("\nRemove or replace with placeholders before publishing. See docs/SANITIZATION.md")
        sys.exit(1)
    print("SCRUB-CHECK PASSED: no environment-specific facts found. Safe to publish.")
    sys.exit(0)


if __name__ == "__main__":
    main()
