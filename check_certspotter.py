#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Stijn Jonker

"""Nagios plugin for incremental Certificate Transparency monitoring."""

from __future__ import annotations

import argparse
from collections import deque
import fcntl
import json
import math
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


VERSION = "1.1.0"
OK = 0
WARNING = 1
UNKNOWN = 3
API_URL = "https://api.certspotter.com/v1/issuances"
DEFAULT_CONFIG = Path("/etc/nagios4/private/certspotter.env")
DEFAULT_STATE = Path("/var/lib/nagios4/certspotter/state.json")
TOKEN_KEY = "CERTSPOTTER_API_TOKEN"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_OUTPUT_CHARS = 8_000
STATE_VERSION = 2
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
    parser.add_argument("--poll-interval", type=float, default=21600,
                        help="Minimum seconds between API polling attempts (default: 21600)")
    parser.add_argument("--warning-duration", type=float, default=3600,
                        help="Seconds to display an issuance WARNING (default: 3600)")
    parser.add_argument("--initialize", action="store_true",
                        help="Explicitly allow a new state/domain baseline; never resets existing cursors")
    parser.add_argument("--show-events", action="store_true",
                        help="Print complete retained events as JSON without contacting the API")
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
        "events": [],
        "last_attempt": None,
        "last_success": None,
        "errors": [],
        "domains": {
            domain: {"cursor": None, "initialized": False} for domain in domains
        },
    }


def load_state(path: Path, domains: list[str], initialize: bool = False) -> dict[str, object]:
    if not path.exists():
        if not initialize:
            raise CheckError("state is missing; restore a backup or explicitly use --initialize")
        return new_state(domains)
    try:
        state = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CheckError(f"cannot read state {path}: {exc}") from exc
    if not isinstance(state, dict) or state.get("version") not in (1, STATE_VERSION):
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
        if domain not in domain_states and not initialize:
            raise CheckError(f"no cursor state for {domain}; use --initialize to add its baseline")
        domain_states.setdefault(domain, {"cursor": None, "initialized": False})
    if state["version"] == 1:
        state.update(version=STATE_VERSION, events=[], last_attempt=None,
                     last_success=None, errors=[])
    for field in ("last_attempt", "last_success"):
        stamp = state.get(field)
        if stamp is not None and (isinstance(stamp, bool) or not isinstance(stamp, (int, float))
                                  or not math.isfinite(stamp) or stamp < 0):
            raise CheckError(f"malformed {field} in state")
    if not isinstance(state.get("errors"), list) or not all(isinstance(e, str) for e in state["errors"]):
        raise CheckError("malformed cached errors in state")
    events = state.get("events")
    if not isinstance(events, list):
        raise CheckError("malformed event history in state")
    for event in events:
        if (not isinstance(event, dict) or not isinstance(event.get("domain"), str)
                or not isinstance(event.get("issuance"), dict)
                or not isinstance(event["issuance"].get("id"), str)):
            raise CheckError("malformed event in state")
        for field in ("detected_at", "announced_at"):
            stamp = event.get(field)
            if stamp is None and field == "announced_at":
                continue
            if (isinstance(stamp, bool) or not isinstance(stamp, (int, float))
                    or not math.isfinite(stamp) or stamp < 0):
                raise CheckError("malformed event timestamp in state")
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
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
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
        queries += 1
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
        if not page:
            value["initialized"] = True
            continue
        if page[-1]["id"] == cursor:
            errors.append(f"{domain}: API returned a non-advancing cursor")
            failed.add(domain)
            continue
        value["cursor"] = page[-1]["id"]
        if initialized:
            findings.extend((domain, issuance) for issuance in page)
        queue.append(domain)

    if queue:
        errors.append("pagination incomplete: " + ", ".join(queue) +
                      "; remaining pages will resume at the next API poll")
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
                output += "\nAdditional issuance details were truncated; full events are retained in state (--show-events)."
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


def evaluate(domains, state, token, args, now=None, fetch=fetch_page):
    """Commit cursors and full events together; cache only changes presentation."""
    now = time.time() if now is None else now
    last = state.get("last_attempt")
    if last is not None and now < last:
        raise CheckError("clock moved backwards relative to the last API attempt")
    due = last is None or now - last >= args.poll_interval
    queries = 0
    if due:
        state["last_attempt"] = now
        findings, errors, queries = poll(domains, state, token, args.timeout,
                                         args.max_queries, fetch)
        state["errors"] = errors
        if not errors and all(state["domains"][d]["initialized"] for d in domains):
            state["last_success"] = now
        known = {(e["domain"], e["issuance"]["id"]) for e in state["events"]}
        for domain, issuance in findings:
            identity = (domain, issuance["id"])
            if identity not in known:
                state["events"].append(dict(domain=domain, issuance=issuance,
                                            detected_at=now, announced_at=None))
                known.add(identity)
    active = [e for e in state["events"] if e["domain"] in domains and
              (e["announced_at"] is None or now - e["announced_at"] < args.warning_duration)]
    findings = [(e["domain"], e["issuance"]) for e in active]
    code, output = format_result(domains, state, findings, state["errors"], queries)
    def stamp(value):
        return "never" if value is None else time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(value))
    output += (f"\nAPI {'polled' if due else 'cached'}; last attempt: {stamp(state.get('last_attempt'))}; "
               f"last complete successful poll: {stamp(state.get('last_success'))}; "
               f"retained events: {len(state['events'])}")
    return code, output, active


def main() -> int:
    args = build_parser().parse_args()
    try:
        if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 30:
            raise CheckError("timeout must be finite, greater than 0 and at most 30 seconds")
        for name in ("poll_interval", "warning_duration"):
            if not math.isfinite(getattr(args, name)) or getattr(args, name) <= 0:
                raise CheckError(f"{name.replace('_', '-')} must be finite and positive")
        if args.max_queries < 1 or args.max_queries > 8:
            raise CheckError("max-queries must be between 1 and 8")
        domains = normalize_domains(args.domain)
        if args.max_queries < len(domains):
            raise CheckError("max-queries must be at least the number of domains")
        args.state_file.parent.mkdir(parents=True, exist_ok=True)
        lock_path = args.state_file.with_suffix(args.state_file.suffix + ".lock")
        with lock_path.open("a", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CheckError("another Cert Spotter check is still running") from exc
            state = load_state(args.state_file, domains, args.initialize)
            if args.show_events:
                print(json.dumps(state["events"], indent=2), flush=True)
                return OK
            token = load_token(args.config)
            checked_at = time.time()
            code, output, active = evaluate(domains, state, token, args, now=checked_at)
            # Event bodies and new cursors reach durable storage before delivery.
            save_state(args.state_file, state)
            print(output, flush=True)
            # Only acknowledge local output after it has been flushed. A crash
            # before this commit replays the event, rather than losing it.
            pending = [event for event in active if event["announced_at"] is None]
            if pending:
                for event in pending:
                    event["announced_at"] = checked_at
                save_state(args.state_file, state)
            return code
    except BrokenPipeError:
        return UNKNOWN
    except (CheckError, OSError) as exc:
        print(f"CertSpotter UNKNOWN: {clean(exc)}", flush=True)
        return UNKNOWN


if __name__ == "__main__":
    raise SystemExit(main())
