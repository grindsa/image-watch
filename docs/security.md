# Security notes

Trivy, DIUN, and Watchtower talk to the Docker daemon through `/var/run/docker.sock`. That socket is the Docker API. A process that can use it can list every container and, when the daemon accepts the call, create a privileged container, mount the host filesystem, and run as root. Treat each of these containers as root on the host. Put them on the same administrative boundary as the Docker daemon. Do not attach extra software, shells, or published ports to them.

## Read-only socket mount

`docker-compose.yml` and `docker-compose.diun.yml` mount the socket with `:ro`. That flag is a filesystem mount option. It is not an authorization policy inside the Docker daemon.

Two practical outcomes show up on real hosts:

- The client opens the socket read-write, the read-only mount rejects the open, and the scan fails with a permission error. Remove `:ro` so the scanner works.
- The client can still send API requests, including requests that create containers. The `:ro` flag did not remove that ability.

Either way, do not describe the Trivy container as unprivileged. The hardening on that service (`read_only` root filesystem, `cap_drop: [ALL]`, `no-new-privileges`, no published ports, `sleep` as the main process) limits what a stray process can do inside the container filesystem. It does not limit what the Docker API will do on the host if the process can speak to the socket.

The official Trivy image runs as a non-root user. This stack sets `user: "0:0"` so the process can write the cache directory mounted at `/root/.cache/trivy` and can open a root-owned socket. Root inside the container plus the socket is host root when the API is reachable.

DIUN uses the same socket, also as root, because it has to inspect containers. Its notifier only writes `updates.json`. It does not pull images and it does not restart them. The DIUN container is still in the trusted set.

## Watchtower

Watchtower needs a writable socket. Digest checks go through the Docker API, and upstream documents that monitor-only mode can still pull images. The compose file therefore mounts the socket without `:ro`.

Automatic recreation is off unless all of the following are true:

1. `WATCHTOWER_ENABLED=true` in `.env`. The nightly cron job then runs Watchtower once, after the report. `install.sh` leaves this false, and no Watchtower container is left running.
2. `WATCHTOWER_MONITOR_ONLY=false` in `.env` (the file ships `true`).
3. The target container has the label `com.centurylinklabs.watchtower.enable=true`. `WATCHTOWER_LABEL_ENABLE=true`, so unlabeled containers are ignored.

`containrrr/watchtower` was archived in December 2025. This stack uses `nickfedor/watchtower`, which keeps the same variables. The original maintainers did not certify forks. Starting Watchtower means trusting that image with the Docker API. Prefer DIUN plus a deploy you run yourself. Use Watchtower only for containers you can afford to have replaced from whatever the tag currently points at.

A bad or compromised tag will be what the container restarts as. Keep databases, queue workers with local state, and one-shot migration containers unlabeled.

## Reports and mail

Image reports list package versions and CVE ids. They are written mode `644`. Any local user who can enter `/srv/data/trivy/reports` can read them. To limit that, put the dashboard account in a group, `chgrp` the directory, and `chmod 750` it. The scan runs as root and can still write. The next scan creates files as mode `644`; the directory mode is what stops other users.

`.env` holds the SMTP password. `install.sh` sets mode `600`. The password is not interpolated into the Trivy, DIUN, or Watchtower containers. Hook processes have `SMTP_PASSWORD` removed. The scan process itself can read it, because it sends the mail. Do not commit `.env`.

The message body repeats CVE titles from the vulnerability database. Those strings are escaped in the HTML part. Links are limited to `http://` and `https://`.

## Images and network

The compose files track `:latest` for Trivy, DIUN, and Watchtower so a routine pull picks up scanner fixes. That also means a pull changes the scanner without a commit in this repository. Pin digests when you want a reviewed image, and still plan to move them when advisories land.

Trivy downloads its database on each scan and opens the image through the Docker API. DIUN opens registries to compare digests. Both need outbound HTTPS. Neither listens on a host port. Watchtower does not enable its HTTP API in this compose file.

Scan only running images. That avoids reporting unused tags, and it also means a stopped container is invisible until it runs again. Turn a container back on and the next night will include it.

## What this setup does not do

It does not firewall the Docker socket, isolate the daemon with a user namespace, or replace a review of the images you deploy. It records CVE counts and available updates for the containers that are already running, and it can mail that record. Acting on it — rebuilding, pinning, or restarting — stays a separate step unless you deliberately enable Watchtower.
