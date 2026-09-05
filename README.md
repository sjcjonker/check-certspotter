# check-certspotter

`check_certspotter.py` is a stateful Nagios plugin that reports newly observed
Certificate Transparency issuances for one or more domains and all their
subdomains. It uses SSLMate's Cert Spotter Certificate Search API and only the
Python standard library.

This is an independent community plugin. It is not affiliated with or endorsed
by SSLMate or Nagios Enterprises.

## What it monitors

The plugin stores the last opaque API cursor for each configured domain. The
first run builds a baseline and intentionally returns OK, so existing historical
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
  --domain example.net
```

The defaults are:

- token file: `/etc/nagios4/private/certspotter.env`
- state file: `/var/lib/nagios4/certspotter/state.json`
- request timeout: 12 seconds
- query budget: 8 API requests per execution

Use `--config`, `--state-file`, `--timeout` and `--max-queries` to override
them. The query budget must be at least the number of configured domains.

## Nagios configuration

[`examples/check_certspotter.cfg`](examples/check_certspotter.cfg) contains a
complete command, service template and service example. Its command checks two
domains in one serialized execution:

```nagios
define command {
    command_name    check_certspotter
    command_line    $USER1$/check_certspotter.py --domain example.com --domain example.net
}
```

Run it hourly. For immediate event notifications, use a volatile service with
one check attempt and WARNING notifications. UNKNOWN is reserved for API,
configuration and state errors.

Before reloading Nagios, always run its configuration preflight command for your
installation.

## Exit codes and output

| Code | State | Meaning |
| ---: | --- | --- |
| 0 | OK | Baseline is being built, or no new issuance was found |
| 1 | WARNING | One or more new issuances were found |
| 3 | UNKNOWN | The API, configuration, state or local runtime failed |

The first output line is short Nagios status text. Each issuance is emitted on
a real subsequent line so Nagios stores it as long plugin output. If an HTML
notification template prints the two characters `\\n`, fix that template to
decode Nagios's escaped `LONGSERVICEOUTPUT`; the plugin itself emits real line
feeds.

## State and recovery

The plugin uses a non-blocking lock to prevent overlapping executions and writes
state atomically with mode `0600`. Back up the state if uninterrupted detection
is important.

Deleting the state file is safe, but the next run starts a fresh baseline and
will not alert on certificates already present at that time. A malformed state
file returns UNKNOWN instead of silently discarding the cursor.

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
