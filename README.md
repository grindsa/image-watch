# image-watch

Self-hosted vulnerability and update monitoring for Docker hosts. Each server scans **running** container images with [Trivy](https://github.com/aquasecurity/trivy), writes JSON for an external dashboard, and can mail a per-container report. [DIUN](https://crazymax.dev/diun/) records newer images. Watchtower is optional and does not recreate containers unless you turn that on.

No commercial services are required. The host needs Docker Compose v2, Python 3.8+, bash, and cron.

## Layout

| Path | Role |
| --- | --- |
| `/srv/stacks/trivy` | Compose files, scripts, env file |
| `/srv/data/trivy/cache` | Trivy vulnerability database |
| `/srv/data/trivy/reports` | `summary.json`, per-image JSON, `updates.json` |
| `/srv/data/trivy/logs` | `scan.log` |

Every JSON document includes `server_id`, so a collector can merge several machines.

## Install

```bash
sudo git clone https://github.com/grindsa/image-watch.git /srv/stacks/trivy
cd /srv/stacks/trivy
sudo ./install.sh
sudoedit /srv/stacks/trivy/.env
sudo /srv/stacks/trivy/scripts/scan.sh
```

Update a server from GitHub with `sudo /srv/stacks/trivy/deploy.sh`. That keeps `.env` and `/srv/data/trivy`, refreshes cron, and recreates the Trivy container.

`install.sh` starts Trivy and installs one cron job, `/etc/cron.d/trivy-scan`, at 03:00 host local time. That job is the only schedule. It scans, and when you set the flags in `.env`, checks for newer images and runs Watchtower in the same run. `sudo ./install.sh --with-diun` sets `DIUN_ENABLED=true`. Watchtower stays off until `WATCHTOWER_ENABLED=true`.

Set `SERVER_ID` to a stable inventory name. Leave `EMAIL_ENABLED=false` until `SMTP_*` is filled in. The mail lists CRITICAL, HIGH, and MEDIUM findings for each running container; the default scan severity includes all three.

## Dashboard files

- `summary.json` — last scan time, totals, one row per image, container names
- `<image>.json` — Trivy report plus `server_id` and the containers using that image
- `updates.json` — DIUN events (`new` / `update`) for images that have a newer digest

Details, exit codes, and the hook directory are in [docs/operations.md](docs/operations.md). The Docker socket risk is in [docs/security.md](docs/security.md). `examples/` holds illustrative output, including a sample mail.

## License

GNU GPL v3. See [LICENSE](LICENSE).
