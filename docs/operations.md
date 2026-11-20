# Operations

The nightly cron job is `/srv/stacks/trivy/scripts/scan.sh`. When `DIUN_ENABLED=true` it checks for newer images first. It then scans images of **running** containers (`docker ps`), writes JSON under `/srv/data/trivy/reports`, and sends email when `EMAIL_ENABLED=true`. Mail goes out for a finished scan, including one where some images failed. It stays unsent when Docker or the Trivy container never produced a new `summary.json`, so an old report is not mailed again. Stopped containers and leftover local images are skipped so old tags do not fill the report.

A second scan exits 0 immediately when the lock file `/srv/data/trivy/logs/scan.lock` is held.

## Commands

```bash
sudo /srv/stacks/trivy/scripts/scan.sh
sudo /srv/stacks/trivy/scripts/scan.sh --skip-email
sudo /srv/stacks/trivy/scripts/send_report.py --dry-run
sudo /srv/stacks/trivy/scripts/send_report.py
sudo /srv/stacks/trivy/scripts/build_summary.py
```

`build_summary.py` rewrites `summary.json` from the image files already on disk. Use it after you copy reports aside; the normal scan builds the summary itself.

Logs:

```bash
sudo tail -f /srv/data/trivy/logs/scan.log
```

Each run records the start, the finish, the image count, the duration, and per-image failures. Timestamps in the log are UTC. Cron starts the job at 03:00 host local time. When `DIUN_ENABLED=true`, that same run checks for newer images first and writes the result to `scan.log`. When `WATCHTOWER_ENABLED=true`, Watchtower runs once after the hooks, and its output is in the same file.

Rotate `scan.log` with `examples/logrotate-trivy` if the file should not grow without bound. `copytruncate` matches the way the script appends.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan finished and email was sent, disabled, or skipped |
| 1 | One or more images failed, or the image scan succeeded and an enabled DIUN or Watchtower pass failed. `summary.json` is still published when the image scan got that far, and email is still attempted |
| 2 | The scan finished and SMTP failed |
| 3 | The scan and the email both failed |
| 4 | Docker, the Trivy container, or the email configuration is not usable |

Hook scripts do not change this code. Their output is appended to `scan.log`.

## JSON contract

`report_schema` is `1`. New fields may appear. `server_id` is present on `summary.json`, every image report, every DIUN event, and `updates.json`.

Vulnerability counts are unique per severity, CVE, package, installed version, fixed version, and target. LOW and UNKNOWN rows are omitted from the counts and from the mail even if a wider `TRIVY_SEVERITY` asked Trivy to emit them. The raw Trivy `Results` array is kept inside the image file.

### summary.json

`scan_time` is the last scan timestamp (UTC, `Z` suffix).

```json
{
  "report_schema": 1,
  "generator": "image-watch",
  "server_id": "edge-01",
  "hostname": "edge-01.internal",
  "scan_time": "2026-11-20T02:00:00Z",
  "finished_at": "2026-11-20T02:01:35Z",
  "scan_duration_seconds": 95,
  "images_scanned": 2,
  "images_failed": 0,
  "critical": 1,
  "high": 1,
  "medium": 1,
  "severity_filter": ["CRITICAL", "HIGH", "MEDIUM"],
  "reports_dir": "/srv/data/trivy/reports",
  "update_status": {"file": "updates.json", "available": 1, "updated_at": "2026-11-20T04:00:00Z"},
  "failures": [],
  "images": [
    {
      "name": "nginx:latest",
      "report_file": "nginx_latest.json",
      "critical": 1,
      "high": 0,
      "medium": 1,
      "status": "ok",
      "error": null,
      "duration_seconds": 40,
      "containers": [
        {"id": "abc111111111", "name": "web-nginx", "compose_project": "web", "compose_service": "nginx"}
      ]
    }
  ]
}
```

`images_scanned` counts every unique running image the job tried, including failures. Totals add successful images once. Two containers that share `nginx:latest` do not double the CVE counts. `status` is `ok` or `error`. On error, `critical` / `high` / `medium` are 0 and `error` has the scanner message.

Image rows are sorted by critical, then high, then medium, then name. Report filenames are the image reference with characters outside `A-Za-z0-9._-` replaced by `_`, for example `nginx:latest` → `nginx_latest.json`.

### Per-image JSON

The file is a Trivy JSON document with these fields added at the top: `report_schema`, `generator`, `server_id`, `hostname`, `image`, `report_file`, `scanned_at`, `duration_seconds`, `containers`, `counts`, `status`, `error`. Read `Results` for the full advisory list. A failed scan still has a file, with `status: "error"` and `Results: []`.

Files for images that are no longer running are removed at the end of the next scan. `updates.json` is left in place.

### updates.json

Written by `scripts/diun-notify.sh` when DIUN sees a new digest. The scan creates an empty file when DIUN has not written one yet.

```json
{
  "report_schema": 1,
  "generator": "image-watch",
  "server_id": "edge-01",
  "hostname": "edge-01",
  "updated_at": "2026-11-20T04:00:00Z",
  "source": "diun",
  "updates": [
    {
      "server_id": "edge-01",
      "observed_at": "2026-11-20T04:00:00Z",
      "status": "update",
      "update_available": true,
      "image": "docker.io/library/nginx:latest",
      "digest": "sha256:...",
      "platform": "linux/amd64",
      "provider": "docker",
      "hub_link": "https://hub.docker.com/_/nginx",
      "created": "2026-11-20 03:00:00 +0000 UTC",
      "container_names": "web-nginx",
      "diun_hostname": "edge-01"
    }
  ]
}
```

`status` is DIUN's value (`new` or `update` for a digest you do not have yet). The file keeps the newest 200 events (`UPDATES_MAX_EVENTS`). `summary.json` → `update_status.available` is the number of those events. An empty list means DIUN has not reported a change. It does not, by itself, prove that the latest check succeeded; the `diun start` / `diun finish` lines in `scan.log` do.

Illustrative copies of these files, and of the email, are in `examples/`. The CVE ids there are placeholders.

## Email

After every successful or partial scan, `scripts/send_report.py` reads `summary.json` and the image reports. The message is one section per running container: image, Compose project/service when the labels exist, then CRITICAL, HIGH, and MEDIUM advisories (package, installed version, fixed version, target, title, link). Containers that share an image each get a section, and the header totals still count the image once.

The subject looks like:

```
[trivy] edge-01: 1 critical, 1 high, 1 medium
```

Set `EMAIL_MAX_ROWS_PER_SEVERITY` to a positive integer to cap each severity in the mail. `0` lists every row. Resend the last scan with `send_report.py`. `--dry-run` prints the plain-text body and does not connect to SMTP.

SMTP settings are in `.env`. See [installation.md](installation.md). A failure to send does not delete the JSON.

## Several servers

Set a different `SERVER_ID` on each host. The dashboard, or the collector hook below, groups files by that field. Hostname is recorded separately so the inventory name and the machine name can differ.

Copy `/srv/data/trivy/reports/` from each host. A later central collector only has to concatenate `summary.json` files and keep the image reports beside them. The schema is the same on every machine.

## Hooks

Executable files in `/srv/stacks/trivy/scripts/hooks.d/` run after the email step. `*.example` files are ignored. The process receives:

| Variable | Value |
| --- | --- |
| `SUMMARY_PATH` | `/srv/data/trivy/reports/summary.json` |
| `REPORTS_DIR` | `/srv/data/trivy/reports` |
| `TRIVY_DATA_DIR` | `/srv/data/trivy` |
| `TRIVY_STACK_DIR` | `/srv/stacks/trivy` |

`SMTP_PASSWORD` is removed from the hook environment. Read `server_id` from `summary.json`.

| Example | Copy to | Purpose |
| --- | --- | --- |
| `slack.sh.example` | `slack.sh` | Post the counts to `SLACK_WEBHOOK_URL` |
| `teams.sh.example` | `teams.sh` | Post the counts to `TEAMS_WEBHOOK_URL` |
| `prometheus-textfile.sh.example` | `prometheus-textfile.sh` | Write `trivy.prom` for node_exporter (`TEXTFILE_DIR`) |
| `central-collector.sh.example` | `central-collector.sh` | `rsync` the report directory to `COLLECTOR/<server_id>/` |

```bash
sudo cp scripts/hooks.d/slack.sh.example /srv/stacks/trivy/scripts/hooks.d/slack.sh
sudo chmod 755 /srv/stacks/trivy/scripts/hooks.d/slack.sh
```

Put `SLACK_WEBHOOK_URL` or `TEAMS_WEBHOOK_URL` in `.env`. The cron job loads that file before it runs hooks. Keep the webhook out of the image reports.

Prometheus gauges from the example:

- `trivy_vulnerabilities{server_id,severity}` for `critical`, `high`, and `medium`
- `trivy_update_notifications{server_id}`

Grafana can graph those textfile metrics. This repository does not ship a Prometheus server or a Grafana dashboard.

## DIUN and Watchtower

Both run only as part of `scan.sh`. DIUN is the update signal the dashboard should read. It runs before the vulnerability scan, so `summary.json` can include that night's `updates.json`. Watchtower, when `WATCHTOWER_ENABLED=true`, runs after the report and the hooks. Monitor-only mode can still pull images; that is a Docker API limitation documented by Watchtower. `WATCHTOWER_MONITOR_ONLY=false` recreates labeled containers during that same run. `WATCHTOWER_ROLLING_RESTART=true` restarts them one at a time. `WATCHTOWER_CLEANUP=false` leaves old images on disk.

Apply the enable label only to stateless services you can roll. A database or a migration container should stay unlabeled so a new image cannot restart it during the nightly job.

A container named `diun` or `watchtower` left over from an older install is removed at the start of the job. Those names used to be long-running schedulers.

## Disk and database

The vulnerability database under `/srv/data/trivy/cache` is reused between nights. Trivy refreshes it at the start of each scan. Image reports are replaced each run; they are not a history. Keep history by copying `reports/` from a hook before the next night, or by shipping it to the collector.

To scan fewer severities, set `TRIVY_SEVERITY=CRITICAL,HIGH` and accept that the mail's MEDIUM sections will be empty.
