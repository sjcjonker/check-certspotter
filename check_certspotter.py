#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Stijn Jonker

"""Nagios plugin for incremental Certificate Transparency monitoring."""

from __future__ import annotations

import argparse
from collections import deque
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from typing import Callable
import urllib.error
import urllib.parse
import urllib.request


VERSION = "1.0.0"
OK = 0
WARNING = 1
UNKNOWN = 3
API_URL = "https://api.certspotter.com/v1/issuances"
DEFAULT_CONFIG = Path("/etc/nagios4/private/certspotter.env")
DEFAULT_STATE = Path("/var/lib/nagios4/certspotter/state.json")
TOKEN_KEY = "CERTSPOTTER_API_TOKEN"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_OUTPUT_CHARS = 8_000
STATE_VERSION = 1
DOMAIN_RE = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)


class CheckError(RuntimeError):
    """The check could not produce a reliable result."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--domain",
        action="append",
        required=True,
        help="Domain to monitor, including all subdomains (repeatable)",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument(
        "--max-queries",
        type=int,
        default=8,
        help="Maximum full-domain API queries per check (default: 8)",
    )
    return parser


def normalize_domains(values: list[str]) -> list[str]:
    domains: list[str] = []
    for value in values:
        domain = value.strip().lower().lstrip(".").rstrip(".")
        if not DOMAIN_RE.fullmatch(domain):
            raise CheckError(f"invalid domain: {value!r}")
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CheckError(f"invalid internationalized domain: {value!r}") from exc
        if domain not in domains:
            domains.append(domain)
    return domains


def load_token(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except OSError as exc:
        raise CheckError(f"cannot read API config {path}: {exc.strerror or exc}") from exc
    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    token = values.get(TOKEN_KEY, "")
    if not token or token.lower() in {"replace-me", "changeme", "placeholder"}:
        raise CheckError(f"{TOKEN_KEY} is missing from {path}")
    if any(character.isspace() for character in token):
        raise CheckError(f"{TOKEN_KEY} contains whitespace")
    return token


def new_state(domains: list[str]) -> dict[str, object]:
    return {
        "version": STATE_VERSION,
        "domains": {
            domain: {"cursor": None, "initialized": False} for domain in domains
        },
    }


def load_state(path: Path, domains: list[str]) -> dict[str, object]:
    if not path.exists():
        return new_state(domains)
    try:
        state = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CheckError(f"cannot read state {path}: {exc}") from exc
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise CheckError(f"unsupported or malformed state in {path}")
    domain_states = state.get("domains")
    if not isinstance(domain_states, dict):
        raise CheckError(f"malformed domain state in {path}")
    for domain, value in domain_states.items():
        if not isinstance(domain, str) or not isinstance(value, dict):
            raise CheckError(f"malformed domain state in {path}")
        cursor = value.get("cursor")
        initialized = value.get("initialized")
        if cursor is not None and not isinstance(cursor, str):
            raise CheckError(f"malformed cursor for {domain} in {path}")
        if not isinstance(initialized, bool):
            raise CheckError(f"malformed initialization flag for {domain} in {path}")
    for domain in domains:
        domain_states.setdefault(domain, {"cursor": None, "initialized": False})
    return state


def save_state(path: Path, state: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".state.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_url(domain: str, cursor: str | None) -> str:
    parameters: list[tuple[str, str]] = [
        ("domain", domain),
        ("include_subdomains", "true"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    if cursor is not None:
        parameters.append(("after", cursor))
    return API_URL + "?" + urllib.parse.urlencode(parameters)


def fetch_page(
    domain: str, cursor: str | None, token: str, timeout: float
) -> list[dict[str, object]]:
    request = urllib.request.Request(
        build_url(domain, cursor),
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": (
                f"check-certspotter/{VERSION} "
                "(+https://github.com/sjcjonker/check-certspotter)"
            ),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        retry_after = exc.headers.get("Retry-After")
        detail = f"HTTP {exc.code}"
        if retry_after:
            detail += f" (retry after {retry_after}s)"
        raise CheckError(detail) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise CheckError(f"request failed: {reason}") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise CheckError("API response exceeded 5 MiB")
    try:
        page = json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CheckError("API returned invalid JSON") from exc
    if not isinstance(page, list):
        raise CheckError("API response is not a JSON array")
    for issuance in page:
        if not isinstance(issuance, dict) or not isinstance(issuance.get("id"), str):
            raise CheckError("API response contains an invalid issuance")
    return page


def poll(
    domains: list[str],
    state: dict[str, object],
    token: str,
    timeout: float,
    max_queries: int,
    fetch: Callable[..., list[dict[str, object]]] = fetch_page,
) -> tuple[list[tuple[str, dict[str, object]]], list[str], int]:
    domain_states = state["domains"]
    assert isinstance(domain_states, dict)
    queue = deque(domains)
    findings: list[tuple[str, dict[str, object]]] = []
    errors: list[str] = []
    queries = 0
    failed: set[str] = set()
    deadline = time.monotonic() + 55.0

    while queue and queries < max_queries:
        domain = queue.popleft()
        if domain in failed:
            continue
        value = domain_states[domain]
        assert isinstance(value, dict)
        cursor = value.get("cursor")
        initialized = value.get("initialized") is True
        remaining = deadline - time.monotonic()
        if remaining <= 0.5:
            errors.append("overall 55s deadline reached")
            break
        try:
            page = fetch(
                domain,
                cursor if isinstance(cursor, str) else None,
                token,
                min(timeout, remaining),
            )
        except CheckError as exc:
            errors.append(f"{domain}: {exc}")
            failed.add(domain)
            continue
        queries += 1
        if not page:
            value["initialized"] = True
            continue
        value["cursor"] = page[-1]["id"]
        if initialized:
            findings.extend((domain, issuance) for issuance in page)
        queue.append(domain)

    return findings, errors, queries


def clean(value: object, limit: int = 180) -> str:
    text = " ".join(str(value).split()).replace("|", "/")
    return text[:limit] + ("..." if len(text) > limit else "")


def describe_issuance(domain: str, issuance: dict[str, object]) -> str:
    raw_names = issuance.get("dns_names")
    names = [clean(name, 120) for name in raw_names] if isinstance(raw_names, list) else []
    issuer_value = issuance.get("issuer")
    issuer = "unknown issuer"
    if isinstance(issuer_value, dict):
        issuer = clean(issuer_value.get("friendly_name", issuer))
    identifier = clean(issuance.get("id", "unknown"), 80)
    dns_text = ", ".join(names[:12]) or "no DNS names returned"
    if len(names) > 12:
        dns_text += f", +{len(names) - 12} more"
    validity = ""
    if issuance.get("not_before") or issuance.get("not_after"):
        validity = (
            f"; valid {clean(issuance.get('not_before', '?'), 40)}"
            f" to {clean(issuance.get('not_after', '?'), 40)}"
        )
    return f"{domain}: issuance {identifier}; CA {issuer}; DNS {dns_text}{validity}"


def format_result(
    domains: list[str],
    state: dict[str, object],
    findings: list[tuple[str, dict[str, object]]],
    errors: list[str],
    queries: int,
) -> tuple[int, str]:
    domain_states = state["domains"]
    assert isinstance(domain_states, dict)
    initializing = [
        domain
        for domain in domains
        if not isinstance(domain_states.get(domain), dict)
        or domain_states[domain].get("initialized") is not True
    ]
    if findings:
        grouped: dict[str, tuple[set[str], dict[str, object]]] = {}
        for domain, issuance in findings:
            identifier = str(issuance["id"])
            if identifier not in grouped:
                grouped[identifier] = (set(), issuance)
            grouped[identifier][0].add(domain)
        affected = sorted({domain for domain, _ in findings})
        first = (
            f"CertSpotter: {len(grouped)} new issuance(s) for "
            + ", ".join(affected)
        )
        details = [
            describe_issuance(",".join(sorted(matched_domains)), item)
            for matched_domains, item in grouped.values()
        ]
        details.extend(f"API error: {clean(error)}" for error in errors)
        output = first
        for detail in details:
            candidate = output + "\n" + detail
            if len(candidate) > MAX_OUTPUT_CHARS:
                output += "\nAdditional issuance details were truncated."
                break
            output = candidate
        return WARNING, output
    if errors:
        return UNKNOWN, "CertSpotter UNKNOWN: " + "; ".join(
            clean(error) for error in errors
        )
    if initializing:
        return OK, (
            f"CertSpotter OK: baseline in progress for {', '.join(initializing)}; "
            f"{queries} API query/queries used, historical issuances do not alert"
        )
    return OK, f"CertSpotter OK: no new issuances for {len(domains)} domains"


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.timeout <= 0 or args.timeout > 30:
            raise CheckError("timeout must be greater than 0 and at most 30 seconds")
        if args.max_queries < 1 or args.max_queries > 8:
            raise CheckError("max-queries must be between 1 and 8")
        domains = normalize_domains(args.domain)
        if args.max_queries < len(domains):
            raise CheckError("max-queries must be at least the number of domains")
        token = load_token(args.config)
        args.state_file.parent.mkdir(parents=True, exist_ok=True)
        lock_path = args.state_file.with_suffix(args.state_file.suffix + ".lock")
        with lock_path.open("a", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CheckError("another Cert Spotter check is still running") from exc
            state = load_state(args.state_file, domains)
            findings, errors, queries = poll(
                domains, state, token, args.timeout, args.max_queries
            )
            save_state(args.state_file, state)
        status, output = format_result(domains, state, findings, errors, queries)
    except (CheckError, OSError) as exc:
        print(f"CertSpotter UNKNOWN: {clean(exc)}")
        return UNKNOWN
    print(output)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
