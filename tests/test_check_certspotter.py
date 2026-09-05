#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Stijn Jonker

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import urllib.parse


REPO = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "check_certspotter", REPO / "check_certspotter.py"
)
assert SPEC is not None and SPEC.loader is not None
plugin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plugin)


class CertSpotterTests(unittest.TestCase):
    def test_first_run_builds_baseline_without_alerting(self) -> None:
        domains = ["example.com", "example.net"]
        state = plugin.new_state(domains)
        responses = {
            ("example.com", None): [{"id": "10"}],
            ("example.com", "10"): [],
            ("example.net", None): [],
        }

        def fetch(domain: str, cursor: str | None, token: str, timeout: float):
            return responses[(domain, cursor)]

        findings, errors, queries = plugin.poll(
            domains, state, "secret", 1, 8, fetch
        )
        status, output = plugin.format_result(domains, state, findings, errors, queries)

        self.assertEqual(status, plugin.OK)
        self.assertIn("no new issuances", output)
        self.assertEqual(findings, [])
        self.assertTrue(state["domains"]["example.com"]["initialized"])
        self.assertEqual(state["domains"]["example.com"]["cursor"], "10")

    def test_new_issuance_warns_with_multiline_details(self) -> None:
        domains = ["example.com"]
        state = {
            "version": 1,
            "domains": {"example.com": {"cursor": "10", "initialized": True}},
        }
        responses = {
            ("example.com", "10"): [
                {
                    "id": "11",
                    "dns_names": ["example.com", "www.example.com"],
                    "issuer": {"friendly_name": "Example CA"},
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2026-04-01T00:00:00Z",
                }
            ],
            ("example.com", "11"): [],
        }

        def fetch(domain: str, cursor: str | None, token: str, timeout: float):
            return responses[(domain, cursor)]

        findings, errors, queries = plugin.poll(
            domains, state, "secret", 1, 8, fetch
        )
        status, output = plugin.format_result(domains, state, findings, errors, queries)

        self.assertEqual(status, plugin.WARNING)
        self.assertTrue(output.startswith("CertSpotter: 1 new issuance"))
        self.assertIn("\nexample.com: issuance 11", output)
        self.assertNotIn(r"\n", output)
        self.assertIn("Example CA", output)
        self.assertIn("www.example.com", output)
        self.assertEqual(state["domains"]["example.com"]["cursor"], "11")

    def test_api_error_does_not_advance_cursor(self) -> None:
        domains = ["example.com"]
        state = {
            "version": 1,
            "domains": {"example.com": {"cursor": "10", "initialized": True}},
        }

        def fetch(domain: str, cursor: str | None, token: str, timeout: float):
            raise plugin.CheckError("HTTP 429 (retry after 60s)")

        findings, errors, queries = plugin.poll(
            domains, state, "secret", 1, 8, fetch
        )
        status, output = plugin.format_result(domains, state, findings, errors, queries)

        self.assertEqual(status, plugin.UNKNOWN)
        self.assertIn("HTTP 429", output)
        self.assertEqual(state["domains"]["example.com"]["cursor"], "10")

    def test_query_budget_is_shared_fairly_between_domains(self) -> None:
        domains = ["example.com", "example.net"]
        state = plugin.new_state(domains)
        calls: list[str] = []

        def fetch(domain: str, cursor: str | None, token: str, timeout: float):
            calls.append(domain)
            return [{"id": str(len(calls))}]

        findings, errors, queries = plugin.poll(
            domains, state, "secret", 1, 2, fetch
        )

        self.assertEqual(calls, domains)
        self.assertEqual(queries, 2)
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])

    def test_same_issuance_across_domains_is_reported_once(self) -> None:
        domains = ["example.com", "example.net"]
        issuance = {
            "id": "42",
            "dns_names": ["example.com", "example.net"],
            "issuer": {"friendly_name": "Example CA"},
        }
        state = {
            "version": 1,
            "domains": {
                domain: {"cursor": "41", "initialized": True} for domain in domains
            },
        }

        status, output = plugin.format_result(
            domains,
            state,
            [("example.com", issuance), ("example.net", issuance)],
            [],
            4,
        )

        self.assertEqual(status, plugin.WARNING)
        self.assertTrue(output.startswith("CertSpotter: 1 new issuance"))
        self.assertEqual(output.count("issuance 42"), 1)

    def test_state_round_trip_and_domain_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            domains = plugin.normalize_domains([".EXAMPLE.COM", "example.com."])
            state = plugin.new_state(domains)
            plugin.save_state(path, state)

            self.assertEqual(domains, ["example.com"])
            self.assertEqual(plugin.load_state(path, domains), state)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_api_url_requests_subdomains_and_expansions(self) -> None:
        query = urllib.parse.parse_qs(
            urllib.parse.urlsplit(plugin.build_url("example.com", "123")).query
        )
        self.assertEqual(query["domain"], ["example.com"])
        self.assertEqual(query["include_subdomains"], ["true"])
        self.assertEqual(query["expand"], ["dns_names", "issuer"])
        self.assertEqual(query["after"], ["123"])

    def test_token_file_rejects_placeholders_and_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "certspotter.env"
            path.write_text("CERTSPOTTER_API_TOKEN=replace-me\n", encoding="utf-8")
            with self.assertRaises(plugin.CheckError):
                plugin.load_token(path)
            path.write_text("CERTSPOTTER_API_TOKEN=bad token\n", encoding="utf-8")
            with self.assertRaises(plugin.CheckError):
                plugin.load_token(path)


if __name__ == "__main__":
    unittest.main()
