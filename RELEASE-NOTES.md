# 1.1.0

- Decouple local monitoring frequency from API polling with `--poll-interval`
  (default 21600 seconds) and `--warning-duration` (default 3600 seconds).
- Expire issuance warnings locally without consuming additional API requests.
- Preserve API/state failures as UNKNOWN, including incomplete pagination.
- Retain complete issuance events alongside their cursors in atomic state v2.
  Pending local output is replayed after interrupted delivery.
- Inspect complete event history offline with `--show-events`.
- Require explicit `--initialize` for absent state or newly added domains.
- Migrate existing v1 state in place without resetting cursors.
- Count failed requests against the query budget and detect stalled cursors.

Upgrade: back up your state files, update the plugin, and schedule local checks
hourly. Use a nonvolatile Nagios service with `notification_interval 0` to avoid
duplicate notifications for cached warnings. Do not add `--initialize` to the
normal Nagios command. Keep state backups for rollback to 1.0.0.

The API still only returns unexpired issuances. Baseline construction suppresses
historical events; OK after warning expiry is not certificate authorization.
