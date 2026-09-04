#!/usr/bin/env python3
"""Fail a public release when environment-specific facts are present."""

import ipaddress
import os
import re
import sys

TEXT_SUFFIXES = (".conf", ".json", ".md", ".ndjson", ".py", ".sh", ".txt", ".xml", ".yml", ".yaml")
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "venv"}
SKIP_FILES = {"scrub_check.py"}
ALLOWED_PRIVATE_CIDRS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
))
IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9])")
INTERNAL_DNS = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:home|internal)\b")
LOCAL_PATH = re.compile(r"(?i)(?:(?:/opt|/srv)/(?!example(?:/|\b))[^\s'\"]*|/home/(?!runner\b|user\b|example\b)[a-z0-9._-]+)")
SECRET_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?(?!\$|<|CHANGE_ME|None|\"\"|'')[A-Za-z0-9!@#$%^&*_\-]{8,}")


def private_address_is_allowed(token):
    if token in ALLOWED_PRIVATE_CIDRS:
        return True
    try:
        address = ipaddress.ip_interface(token).ip
        if any(address in network for network in DOCUMENTATION_NETWORKS):
            return True
        return not address.is_private
    except ValueError:
        return True


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = []
    for directory, directories, files in os.walk(root):
        directories[:] = [name for name in directories if name not in SKIP_DIRS]
        for name in files:
            if name in SKIP_FILES or not name.endswith(TEXT_SUFFIXES):
                continue
            path = os.path.join(directory, name)
            try:
                lines = open(path, encoding="utf-8", errors="ignore")
            except OSError:
                continue
            with lines:
                for number, line in enumerate(lines, 1):
                    for match in INTERNAL_DNS.finditer(line):
                        hits.append((path, number, "internal DNS name"))
                    if LOCAL_PATH.search(line):
                        hits.append((path, number, "operator-local filesystem path"))
                    if SECRET_ASSIGNMENT.search(line):
                        hits.append((path, number, "possible hardcoded secret"))
                    for match in IPV4.finditer(line):
                        token = match.group(0)
                        if not private_address_is_allowed(token):
                            hits.append((path, number, "specific private IPv4 address"))
    if hits:
        print(f"SCRUB-CHECK FAILED: {len(hits)} possible environment leak(s)")
        for path, number, description in hits:
            print(f"  {path}:{number} [{description}]")
        return 1
    print("SCRUB-CHECK PASSED: no environment-specific facts found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
