# Installation

Run this on each Docker host. The paths are the same everywhere so a dashboard can collect them by `server_id`.

## Requirements

- Linux with cron (`/etc/cron.d`)
- Docker Engine and the Docker Compose v2 plugin (`docker compose version`)
- Python 3.8 or newer (`python3`)
- bash
- `flock` from util-linux (the scan continues with a warning if it is missing)
- Outbound HTTPS so Trivy can download its vulnerability database and, if you enable DIUN, so DIUN can reach the registries

Trivy is not installed on the host. The scan runs inside `aquasec/trivy:latest`.

## Directories

```
/srv/stacks/trivy/
  docker-compose.yml
  docker-compose.diun.yml
  docker-compose.watchtower.yml
  .env
  scripts/
  cron/
  docs/

/srv/data/trivy/
  cache/          # Trivy DB and scan temp files
  reports/        # JSON the dashboard reads
  logs/           # scan.log
  diun/           # DIUN database, created even if DIUN is not started
```

Logs live under `/srv/data/trivy/logs` on every distribution. If a local policy wants `/var/log/trivy`, symlink that path at the data directory. Do not point the scanner at a different data directory unless you also edit the volume lines in the compose files.

## Install the stack

From a checkout of this repository:

```bash
sudo ./install.sh
```

That copies the tree to `/srv/stacks/trivy` when you are not already there, creates the data directories, copies `.env.example` to `.env` when `.env` is missing, installs `/etc/cron.d/trivy-scan`, and starts the Trivy container. DIUN and Watchtower are not left running. If an older install enabled `trivy-scan.timer`, `install.sh` disables that timer and removes its unit files so the scan cannot run twice. A leftover container named `diun` or `watchtower` is removed, and the matching `DIUN_ENABLED` or `WATCHTOWER_ENABLED` flag is set so the cron job takes over that step.

Useful flags:

| Flag | Effect |
| --- | --- |
| `--with-diun` | Set `DIUN_ENABLED=true` so the cron job also checks for newer images |
| `--no-start` | Write files and the cron job only. Do not call Docker. |

Cron runs `/srv/stacks/trivy/scripts/scan.sh` at 03:00 in the host's local timezone. One line is the whole schedule: the vulnerability scan, the optional DIUN check, and the optional Watchtower pass. A host that is powered off at 03:00 skips that night. To keep a fleet from hitting registries at the same minute, edit the minute field in `/etc/cron.d/trivy-scan` on each machine.

## Configure

Edit `/srv/stacks/trivy/.env` and keep it mode `600`. `install.sh` sets that mode. The file is a list of `KEY=value` lines. Double quotes are removed; `$` is not expanded. Use double quotes around passwords that contain spaces or `#`.

Set at least:

```
SERVER_ID=edge-01
TZ=UTC
```

`SERVER_ID` is copied into every JSON file and into the email subject. Use a name that stays stable if the hostname changes. An empty `SERVER_ID` falls back to the hostname for that run.

`TZ` is the timezone used inside the DIUN and Watchtower containers when those steps run. Cron itself uses the host clock. Set `TZ` to the host timezone, or run the host in UTC, so container log lines match 03:00.

Email stays off until you set:

```
EMAIL_ENABLED=true
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_TLS=starttls
SMTP_USER=scanner
SMTP_PASSWORD="replace-me"
SMTP_FROM=scanner@example.com
SMTP_TO=ops@example.com
```

`SMTP_TO` accepts a comma-separated list. `SMTP_TLS` is `starttls` (587), `ssl` (465), or `none` for a relay on a private network. Certificate checks stay on unless `SMTP_TLS_INSECURE=true`. A private CA can be named with `SMTP_CA_FILE`.

The default severity is `CRITICAL,HIGH,MEDIUM`. The mail only has rows for those three levels, so leave `MEDIUM` in the list if you want it in the message.

## First scan

```bash
sudo /srv/stacks/trivy/scripts/scan.sh
```

The first run downloads the vulnerability database into `/srv/data/trivy/cache` and can take several minutes. When it finishes:

```bash
sudo python3 -m json.tool /srv/data/trivy/reports/summary.json | head
sudo tail -n 50 /srv/data/trivy/logs/scan.log
```

`summary.json` should contain your `server_id`, `scan_time`, and one entry per running image. Preview the mail without sending it:

```bash
sudo /srv/stacks/trivy/scripts/send_report.py --dry-run
```

## Scheduler

`install.sh` installs this single cron job:

```
0 3 * * * root /srv/stacks/trivy/scripts/scan.sh
```

The file on disk is `/etc/cron.d/trivy-scan`. Run it by hand with `sudo /srv/stacks/trivy/scripts/scan.sh`. Output is appended to `/srv/data/trivy/logs/scan.log`.

## DIUN

DIUN compares running images with the registry and appends to `/srv/data/trivy/reports/updates.json` when a newer digest exists. It does not pull or restart anything, and it does not stay running. The same 03:00 job runs it before the vulnerability scan when `DIUN_ENABLED=true`.

```bash
sudo ./install.sh --with-diun
```

On an existing install, set `DIUN_ENABLED=true` in `/srv/stacks/trivy/.env`. The next cron run picks it up. The first check records a baseline and does not notify (`DIUN_WATCH_FIRSTCHECKNOTIF=false`), so an empty `updates.json` after that first check is expected. DIUN's log lines are in `scan.log`.

## Watchtower

Leave this off unless you have read [security.md](security.md). The compose file uses `nickfedor/watchtower` because `containrrr/watchtower` was archived in December 2025. The environment variables are the same. The default is monitor-only, and only containers with this label are eligible:

```yaml
labels:
  - com.centurylinklabs.watchtower.enable=true
```

Set `WATCHTOWER_ENABLED=true` to make the same cron job run Watchtower once, after the report is written. With `WATCHTOWER_MONITOR_ONLY=true` it does not recreate workloads. Recreating containers also requires `WATCHTOWER_MONITOR_ONLY=false`. Do that only for services you are willing to restart from a newly pulled image. There is no Watchtower clock of its own.

## Uninstall

```bash
sudo docker compose -f /srv/stacks/trivy/docker-compose.yml down
sudo docker rm -f diun watchtower
sudo rm -f /etc/cron.d/trivy-scan
sudo systemctl disable --now trivy-scan.timer 2>/dev/null || true
sudo rm -f /etc/systemd/system/trivy-scan.service /etc/systemd/system/trivy-scan.timer
sudo systemctl daemon-reload 2>/dev/null || true
```

`/srv/data/trivy` is left in place. Delete it when you no longer need the reports or the vulnerability database.

## Troubleshooting

**`docker.sock: permission denied` or Trivy cannot list images.** Some Docker versions reject API calls when the socket mount is read-only. Remove `:ro` from the Trivy (and DIUN) socket volume. Treat that container as root on the host either way; the flag is not an authorization policy. See [security.md](security.md).

**`docker exec trivy trivy --version` fails immediately.** The Trivy service uses a read-only root filesystem and `cap_drop: [ALL]`. Confirm `/srv/data/trivy/cache` exists and is writable by root. If the engine still refuses the exec, remove `read_only` and `cap_drop` from `docker-compose.yml` and start the stack again.

**Email exit code 4.** `EMAIL_ENABLED=true` and `SMTP_HOST`, `SMTP_FROM`, or `SMTP_TO` is empty or not an address. The scan JSON is still written. Fix `.env` and resend with `sudo /srv/stacks/trivy/scripts/send_report.py`.

**An old timer is still installed.** `install.sh` disables `trivy-scan.timer` and deletes its unit files. If a scan still runs twice, check `systemctl list-timers trivy-scan.timer` and `crontab -l`.

**Python older than 3.8.** Install a newer `python3`. The scripts use the standard library only.
