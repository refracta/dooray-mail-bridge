# Docker Compose deployment

Docker builds the Go binary in a separate stage. The runtime image contains only
the binary and trusted CA certificates, runs as UID/GID `10001:10001`, and has a
read-only root filesystem. Cookies, mailbox UIDs and the MIME cache persist in
the Compose `data` volume. The build context excludes dotenv files, keys, local
mail and test artifacts.

## First start

```sh
git clone https://github.com/refracta/dooray-mail-bridge.git
cd dooray-mail-bridge
cp .env.example .env
chmod 600 .env
mkdir -p certs
```

Set `KAIST_ID`, `KAIST_PASSWORD`, `DOORAY_EMAIL` and either the HTTP or IMAP
verification source in `.env`, as described in the [README](../README.md).
Single-quote values containing `$` so Compose does not interpolate passwords.

Copy a trusted certificate for your mail hostname to `certs/fullchain.pem` and
its private key to `certs/privkey.pem`. Resolve any source symlinks when copying;
links into an unmounted Let's Encrypt archive will not work inside the container.
The container must be able to traverse the directory and read the two files:

```sh
sudo chown -R 10001:10001 certs
sudo chmod 700 certs
sudo chmod 600 certs/fullchain.pem certs/privkey.pem
docker compose build
docker compose run --rm bridge -check
docker compose up -d
docker compose logs --tail 30 bridge
```

The connection check is a one-time upstream login before starting the service.
Do not run it periodically against a running instance's data volume: independent
login processes can compete over verification and persisted cookies.

Compose supplies the container's data path, listeners and certificate paths.
The corresponding standalone settings in `.env` are overridden. The certificate
directory is mounted read-only; change its host location with `TLS_CERT_DIR`.

## Remote clients and forwarding

By default, published ports listen only on the host's loopback interface. To
allow remote clients, add the host's LAN address and desired ports to `.env`:

```dotenv
BIND_ADDR=192.0.2.10
IMAP_PORT=1993
SMTP_PORT=1465
```

Recreate the service with `docker compose up -d`. In the router, forward TCP 1993
and TCP 1465 to the same ports on that LAN host. Use unoccupied external ports
if these are already assigned. Allow these ports through the host firewall, and
point the mail hostname's DNS record at the router's public address. The DNS
record must permit ordinary TCP traffic, not an HTTP-only CDN proxy.

Both ports use **implicit SSL/TLS**, not STARTTLS. Clients use the KAIST ID or
configured Dooray email address and the KAIST password for both IMAP and SMTP.
Disable the client's extra Sent-folder copy because Dooray already stores it.

Some NAS hosts have exhausted Docker's automatic address pools. Add an untracked
`compose.override.yaml` to use Docker's existing bridge network without creating
another network:

```yaml
services:
  bridge:
    network_mode: bridge
```

## Updates, certificate renewal and backups

```sh
git pull --ff-only
docker compose up -d --build
docker compose logs --tail 30 bridge
```

After renewing the certificate, copy both renewed files into the mounted
directory, preserve their ownership/permissions, and run:

```sh
docker compose restart bridge
```

The process loads its certificate at startup. Attach the copy/restart step to the
certificate manager's renewal hook; do not rely on a one-time certificate copy.
The included host helper validates that the certificate and key match, copies
changed files with the container's ownership, and restarts an existing bridge:

```sh
sudo ./scripts/sync-certificates.sh /etc/letsencrypt/live/mail.example.com
```

It does nothing when both files are unchanged. If `TLS_CERT_DIR` points elsewhere,
pass that host directory as the second argument. For older NAS installations,
set `DMB_COMPOSE_BIN=/usr/local/bin/docker-compose` when invoking the helper.

Back up `.env`, the private certificate directory and the `data` volume. Stop the
bridge before copying its bbolt database, then restart it. Restoring the data
volume preserves IMAP UIDs; keep it when rebuilding the container. Ordinary
`docker compose down` keeps it, while `docker compose down -v` deletes it.

`restart: unless-stopped` brings the service back after a daemon/host restart.
Logs rotate at 10 MiB with three files retained.

The deployment uses [Compose service settings](https://docs.docker.com/reference/compose-file/services/)
and [multi-stage builds](https://docs.docker.com/build/building/multi-stage/).
