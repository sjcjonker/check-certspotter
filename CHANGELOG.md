# Changelog

All notable changes to this project will be documented in this file.

## 1.1.0 - 2026-10-14

See [1.1.0 release notes](RELEASE-NOTES.md) for changes, upgrade requirements
and monitoring limitations. The publication helper reads that file directly.

## 1.0.0 - 2026-09-05

- Initial public release.
- Monitor multiple domains and all their subdomains through the Cert Spotter API.
- Persist an opaque cursor per domain and suppress alerts while building the initial baseline.
- Report new issuances as Nagios WARNING results with issuer, DNS names and validity dates.
- Serialize concurrent checks and update state atomically.
