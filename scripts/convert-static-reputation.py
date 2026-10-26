#!/usr/bin/env python3
"""Convert an exported static reputation JSON snapshot into reviewed canonical import artifacts.

This offline tool is never linked into the server. It does not open Redis or
load production credentials. Its output is a proposal for authenticated override
import and IP override network configuration, not an automatic deployment.
Apply the overrides with `contrib/client/nauthilus-admin.py reputation override
import <artifact>`.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys

BANDS = {"trusted", "neutral", "blocked"}
ORIGIN = "cutover.static_reputation_v4"


def exact_keys(value, required, optional=()):
    """Reject incomplete or unknown offline input fields before conversion."""
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError("invalid static snapshot shape")


def domain(value):
    """Accept only the canonical ASCII domain identities used by the source snapshot."""
    if not isinstance(value, str) or len(value) > 253 or not value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("invalid canonical domain")
    return value


def network(value):
    """Preserve exact canonical CIDRs without widening host bits or mapped IPv6 input."""
    parsed = ipaddress.ip_network(value, strict=True)
    if str(parsed) != value or (parsed.version == 6 and parsed.network_address.ipv4_mapped):
        raise ValueError("invalid canonical network")
    return value


def audit_text(value):
    """Bound operator audit identifiers without accepting controls or surrounding whitespace."""
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 128 or value.strip() != value or any(ord(x) < 32 or ord(x) == 127 for x in value):
        raise ValueError("invalid operator audit metadata")
    return value


def stable_suffix(kind, value):
    """Create a bounded deterministic identifier without exposing the original subject in its name."""
    return hashlib.sha256((kind + "\0" + value).encode()).hexdigest()[:24]


def convert(snapshot, creator, audit_prefix, expires_at=0):
    """Produce exact overrides and the longest-prefix IP override network catalog."""
    exact_keys(snapshot, (), ("domains", "client_networks"))
    audit_text(creator)
    audit_text(audit_prefix)
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or not 0 <= expires_at <= 100_000_000_000:
        raise ValueError("invalid absolute expiry")
    result = {"schema": "reputation-static-import.v1", "overrides": [], "ip_override_networks": []}
    seen = set()
    for key, field, kind, validate in (("domains", "domain", "dns_domain", domain), ("client_networks", "cidr", "network", network)):
        entries = snapshot.get(key, [])
        if not isinstance(entries, list) or len(entries) > (128 if kind == "network" else 256):
            raise ValueError("static snapshot cardinality exceeded")
        for entry in entries:
            exact_keys(entry, (field, "reputation"))
            subject = validate(entry[field])
            if entry["reputation"] not in BANDS or (kind, subject) in seen:
                raise ValueError("invalid or duplicate classification")
            seen.add((kind, subject))
            correlation = audit_prefix + ":" + stable_suffix(kind, subject)
            audit_text(correlation)
            result["overrides"].append({"kind": kind, "subject": subject, "band": entry["reputation"], "reason": "static.classification", "creator": creator, "audit_id": correlation, "origin": ORIGIN, "expires_at": expires_at})
            if kind == "network":
                result["ip_override_networks"].append(subject)
    result["overrides"].sort(key=lambda x: (x["kind"], x["subject"]))
    result["ip_override_networks"].sort(key=lambda x: (-ipaddress.ip_network(x).prefixlen, x))
    return result


def unique_object(pairs):
    """Reject duplicate JSON keys so no source classification disappears silently."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate input key")
        result[key] = value
    return result


def main():
    """Write a restrictive new output file without overwriting an existing review artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="exported static module config as JSON, without credentials")
    parser.add_argument("output", help="new canonical import artifact, created with mode 0600")
    parser.add_argument("--creator", required=True)
    parser.add_argument("--audit-prefix", required=True)
    parser.add_argument("--expires-at", type=int, default=0, help="absolute Unix expiry; zero means explicitly non-expiring")
    args = parser.parse_args()
    with open(args.input, encoding="utf-8") as source:
        raw = source.read(1_048_577)
    if len(raw.encode()) > 1_048_576:
        raise ValueError("snapshot exceeds input bound")
    output = convert(json.loads(raw, object_pairs_hook=unique_object), args.creator, args.audit_prefix, args.expires_at)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        json.dump(output, destination, indent=2, sort_keys=True)
        destination.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError):
        print("conversion failed: invalid input or unavailable output", file=sys.stderr)
        sys.exit(1)
