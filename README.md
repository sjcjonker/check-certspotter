# check-certspotter

`check_certspotter.py` is a stateful Nagios plugin that reports newly observed
Certificate Transparency issuances for one or more domains and all their
subdomains. It uses SSLMate's Cert Spotter Certificate Search API and only the
Python standard library.

This is an independent community plugin. It is not affiliated with or endorsed
by SSLMate or Nagios Enterprises.

## What it monitors

The plugin stores the last opaque API cursor for each configured domain. The
first explicitly initialized run builds a baseline, so existing historical
certificates do not generate alerts. Later issuances return WARNING and include
the issuer, DNS names and validity period in Nagios long output.

This complements, but does not replace, active HTTPS certificate-expiry checks.
Certificate Transparency also does not indicate whether an issuance is
authorized or whether a certificate has been revoked.

## Requirements

- Linux or another system with `fcntl.flock`
- Python 3.9 or newer
- Nagios Core, Nagios XI, Icinga, Naemon or another compatible monitoring engine
- A Cert Spotter Certificate Search API token
- HTTPS access to `api.certspotter.com`

## Installation

Install the executable in the monitoring plugin directory:

```bash
sudo install -o root -g root -m 0755 check_certspotter.py \
  /usr/lib/nagios/plugins/check_certspotter.py
```

Create a private token file and a state directory. Replace `nagios` if your
monitoring daemon uses a different account or group:

```bash
sudo install -d -o root -g nagios -m 0750 /etc/nagios4/private
sudo install -d -o nagios -g nagios -m 0750 /var/lib/nagios4/certspotter
sudoedit /etc/nagios4/private/certspotter.env
sudo chown root:nagios /etc/nagios4/private/certspotter.env
sudo chmod 0640 /etc/nagios4/private/certspotter.env
```

The token file contains exactly this setting:

```text
CERTSPOTTER_API_TOKEN=your-api-token
```

Do not pass the token on the command line: process arguments can be visible to
other local users. Do not commit the token or generated state file.

Verify the check as the monitoring user:

```bash
sudo -u nagios /usr/lib/nagios/plugins/check_certspotter.py \
  --domain example.com \
  --domain example.net --initialize
```

The defaults are:

- token file: `/etc/nagios4/private/certspotter.env`
- state file: `/var/lib/nagios4/certspotter/state.json`
- request timeout: 12 seconds
- query budget: 8 attempted API requests per polling execution
- API polling interval: 21600 seconds (6 hours)
- issuance WARNING duration: 3600 seconds (1 hour)

Use `--config`, `--state-file`, `--timeout`, `--max-queries`, `--poll-interval`
and `--warning-duration` to override them. Time values are in seconds and must
be finite and positive. The query budget must be at least the number of configured
domains. There is no new token-file setting: the timing options are command-line
arguments, making separate monitoring commands straightforward.

## Nagios configuration

[`examples/check_certspotter.cfg`](examples/check_certspotter.cfg) contains a
complete command, service template and service example. Its command checks two
domains in one serialized execution:

```nagios
define command {
    command_name    check_certspotter
    command_line    $USER1$/check_certspotter.py --domain example.com --domain example.net --poll-interval 21600 --warning-duration 3600
}
```

Run the local check hourly. It only contacts the API when at least six hours have
elapsed since the last attempt; other runs use the saved result. An issuance
WARNING expires at the first local check at or after its configured duration.
Scheduling delays can delay that transition. API errors do not expire to OK,
and failed API attempts also wait for the polling interval before retrying.

Use a **nonvolatile** service (`is_volatile 0`), one check attempt,
`notification_interval 0`, and WARNING notifications. Cached warnings must not
send repeated notifications. Keep the warning duration shorter than the polling
interval and schedule checks frequently enough to observe the recovery to OK
before the next poll. Returning OK means the event display has expired, not that
anyone has approved the certificate.

UNKNOWN is reserved for API, configuration, state errors and unfinished pagination.
If new events and API errors occur together, the initial WARNING includes both;
after the event expires, the unresolved error remains UNKNOWN. If API failures
must also notify, include `u` in your service's `notification_options`.

Before reloading Nagios, always run its configuration preflight command for your
installation.

## Exit codes and output

| Code | State | Meaning |
| ---: | --- | --- |
| 0 | OK | Complete baseline or no active issuance warning |
| 1 | WARNING | One or more new/pending issuances, or an unexpired cached event warning |
| 3 | UNKNOWN | The API, configuration, state or local runtime failed |

The first output line is short Nagios status text. Each issuance is emitted on
a real subsequent line so Nagios stores it as long plugin output. If an HTML
notification template prints the two characters `\\n`, fix that template to
decode Nagios's escaped `LONGSERVICEOUTPUT`; the plugin itself emits real line
feeds.

## State and recovery

The plugin uses a non-blocking lock to prevent overlapping executions. State is
written atomically with mode `0600`, with both the file and its parent directory
synced to disk. Cursors and complete event bodies are committed together before
printing a result. Pending output is acknowledged only after stdout is flushed.
An interruption before acknowledgement replays the warning rather than silently
skipping it. This guarantees local retention/replay, not successful Nagios
notification or email delivery: those remain outside the plugin's control.

State version 2 stores:

- `domains`: an opaque cursor and initialization flag per domain.
- `last_attempt`, `last_success`: API-attempt time and last fully successful poll.
- `errors`: cached errors that remain visible until a successful poll clears them.
- `events`: full issuance objects with domain, detection time and local output
  acknowledgement time. Events remain available after their WARNING expires.

Existing version 1 state migrates automatically and keeps its cursors. Back up
state before upgrading; version 1.0.0 cannot read version 2 state. To roll back,
restore the old state backup with the old plugin. Events discovered after that
backup may be replayed on a subsequent poll.

A missing state file or a new domain without state returns UNKNOWN. Restore a
backup to preserve continuity, or run `--initialize` explicitly to build a new
baseline. Do not put `--initialize` in the recurring monitoring command. It does
not reset existing cursors, but permits initialization of absent state/domains.
Baseline pages are deliberately not treated as new events, including issuances
that arrive while a multi-run baseline is still being built. Incomplete baseline
pagination is UNKNOWN and resumes on the next scheduled API poll.

After each page, the last issuance ID is used as `after` for the next request.
This follows discovery order, including late-discovered older certificates.
Budget/deadline exhaustion is reported and the next poll resumes at the saved
cursor. No cursor is advanced for a failed page. API errors count against the
query budget. The fixed overall polling deadline is 55 seconds.

Complete event history is retained **without automatic deletion** in the state
file, even when Nagios output is truncated. Include these files in backups and
monitor storage growth on high-volume domains. Display the history without an
API request or access to the token file:

```bash
sudo -u nagios /usr/lib/nagios/plugins/check_certspotter.py \
  --domain example.com --state-file /var/lib/nagios4/certspotter/example.com.json \
  --show-events
```

The API only returns unexpired issuances. Certificates that expire before the
next poll, upstream omissions, and CT indexing delays remain monitoring limits.
Six-hour polling can also delay detection by approximately six hours plus upstream
indexing/scheduling time. See the [API reference](https://sslmate.com/help/reference/ct_search_api_v1).

## Upgrading from 1.0.0

1. Back up the state files while the checks are quiescent.
2. Install the 1.1.0 plugin and preserve the existing token and state paths.
3. Change the local check interval to 60 minutes and `is_volatile` to `0`.
4. Set `notification_interval 0` and add the timing arguments to the command.
5. Run tests and Nagios configuration preflight before reloading.

The first upgraded run contacts the API because v1 has no polling timestamp;
subsequent local runs respect the configured interval. Existing cursors do not
reset. The new check emits last-attempt and last-success times on subsequent
output lines so cached OK is not confused with a fresh API lookup.

## Testing

The test suite performs no network calls:

```bash
python3 -m py_compile check_certspotter.py
python3 -m unittest discover -s tests -v
```

## License

Copyright (C) 2026 Stijn Jonker.

This project is free software licensed under the GNU General Public License,
version 3 or (at your option) any later version. See [`LICENSE`](LICENSE).
