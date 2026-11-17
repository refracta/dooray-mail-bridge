# dooray-mail-bridge

A lightweight bridge that exposes Dooray webmail as IMAP and SMTP. It talks to
Dooray and KAIST SSO over HTTP, including email verification and session renewal.
It runs as one Go executable with local state files. No browser, JavaScript
runtime, or separate database server is required.

The initial authentication provider is **KAIST SSO**. Dooray's public-cloud
service does not provide native IMAP for public institutions, according to its
[mail service documentation](https://dooray.co.kr/main/service/mail/).

## Features

- KAIST ID/password login, fresh email verification codes, persistent cookies,
  expiry detection, and serialized session recovery.
- Verification codes from an HTTPS service or directly from the external
  verification mailbox over IMAP/TLS, without a separate code service.
- The same KAIST ID/password authenticates both IMAP and SMTP. The full configured
  mail address is also accepted as the username.
- IMAP folders, message search, original MIME/attachments, partial fetches,
  read/unread and important flags, copy/move, deletion, import, and IDLE updates.
- Persistent mailbox UIDs/UIDVALIDITY, subscriptions, and an on-demand MIME cache.
- SMTP submission through Dooray's draft/upload/send flow, with text, HTML,
  file attachments, inline/CID images, and envelope-recipient handling.
- TLS listeners, an upstream connection check, and graceful shutdown.

This is an independent integration with Dooray's **internal web API**, not an
official Dooray SDK. Authentication and API changes can require updates.

## Build and configure

Requires Go 1.26 or newer to build. The compiled service needs only OS CA
certificates and a writable data directory.

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/dooray-mail-bridge ./cmd/dooray-mail-bridge
cp .env.example .env
chmod 600 .env
# Set KAIST credentials, a verification code source, and TLS paths in .env.
./bin/dooray-mail-bridge -check
./bin/dooray-mail-bridge
```

Environment variables take precedence over `.env`. Use `-env-file /path/to/file`
to select another dotenv file. Credentials, cookies, caches, and TLS keys belong
outside version control; the default paths are ignored by Git.

### Verification code source

Choose one of these methods. `KAIST_CODE_SOURCE=http` uses an HTTPS code service;
`KAIST_CODE_SOURCE=imap` reads the verification mailbox directly. If the source is
omitted, a nonempty `KAIST_CODE_URL` takes precedence over IMAP configuration.

For the HTTP method, `KAIST_CODE_URL` must return the latest verification mail:

```json
{
  "code": "012345",
  "id": "unique-message-id",
  "date": "2026-01-01T00:00:01Z",
  "serverTime": 1767225602000
}
```

`serverTime` is Unix time in milliseconds. The service snapshots this endpoint
before requesting a verification email, then accepts only a different, fresh
message. `KAIST_CODE_TOKEN` optionally sets a bearer token. Use a mailbox monitor
that restricts codes to the intended KAIST account. Codes and credentials are
never logged.

For direct IMAP access, configure the **external mailbox registered in KAIST
SSO**. These credentials belong to that mailbox, separately from the KAIST
credentials used by mail clients connecting to the bridge:

```dotenv
KAIST_CODE_SOURCE=imap
KAIST_CODE_IMAP_ADDR=imap.naver.com:993
KAIST_CODE_IMAP_USERNAME=your-verification-mailbox@naver.com
KAIST_CODE_IMAP_PASSWORD=your-mailbox-or-app-password
KAIST_CODE_IMAP_MAILBOX=INBOX
KAIST_CODE_IMAP_RECIPIENT=your-verification-mailbox@naver.com
```

The address must include a port and support implicit TLS with a trusted
certificate. Enable IMAP in the mailbox provider; use an app password if the
provider requires one. `KAIST_CODE_IMAP_MAILBOX` defaults to `INBOX` and the
recipient defaults to the IMAP username if it is an email address. The recipient
must match the destination registered in SSO, even when the IMAP login name is
different. `KAIST_CODE_URL` is not used in explicit IMAP mode.

The bridge connects only during verification, selects the mailbox read-only,
and records its UIDVALIDITY/UIDNEXT before requesting a code. It reads only new
candidate messages with `BODY.PEEK`, validates the sender, decoded KAIST subject,
recipient and freshness, and closes the connection afterward. It does not mark
mail read, delete messages, or keep a copy of the mailbox. If UIDVALIDITY changes,
the attempt stops rather than accepting a code from a reset mailbox.
Some providers, including Naver, report UIDVALIDITY as zero. This is supported;
the bridge also rejects a backward UIDNEXT and still checks message timestamps.
A mailbox reset that reuses the same validity value and has already advanced
past the previous UID watermark cannot be identified from UID metadata alone.

## Mail client settings

| Setting | IMAP | SMTP |
| --- | --- | --- |
| Server | Host running the bridge | Host running the bridge |
| Default port | 1993 | 1465 |
| Connection security | SSL/TLS | SSL/TLS |
| Authentication | Normal password | Normal password |
| Username | KAIST ID or configured mail address | Same |
| Password | KAIST password | Same |

Defaults bind only to `127.0.0.1`. For remote clients, configure the listener
addresses and a trusted certificate. These ports use **implicit TLS**, not
STARTTLS. SMTP recipients are submitted through the authenticated Dooray account;
this is not an unauthenticated relay.

For local development, `ALLOW_INSECURE_LOCAL=true` permits plaintext only on
numeric loopback addresses. Select plaintext in the local test client too.

Dooray saves sent messages itself. Disable the mail client's extra Sent-folder
copy to avoid duplicate sent messages.

## Behavior and limits

- `BODY.PEEK` and `EXAMINE` preserve read state. Normal body fetches and `STORE`
  synchronize `\Seen` and `\Flagged` with Dooray.
- `\Deleted` is a durable local marker until `EXPUNGE`. Expunging permanently
  removes the marked messages; moving to `Trash` keeps them recoverable.
- `\Answered` and `\Draft` are exposed as read-only provider metadata. Unsupported
  flag changes fail explicitly.
- Saving drafts with `APPEND \Draft` is not supported. COPY of a message with a
  bridge-only imported date override or `\Deleted` marker is also rejected;
  ordinary provider messages can be copied, and MOVE preserves those attributes.
- IDLE updates are generated by polling; `POLL_INTERVAL` defaults to 30 seconds.
- Nonempty SUBJECT searches use decoded message metadata, so searching by title
  does not download unrelated bodies or attachments. Other content searches
  populate the on-demand MIME cache as needed.
- MIME downloads preserve original bytes. SMTP submission is reconstructed via
  Dooray's composer, so arbitrary raw headers and original MIME structure are not
  guaranteed to survive sending.
- UIDPLUS is not advertised because Dooray copy operations do not provide a
  reliable source/destination UID mapping.
- A timed-out send may already have been accepted upstream. The bridge never
  automatically resends an ambiguous submission.
- Account switching requires a separate data directory. Each instance serves one
  configured account.

## Tests

```sh
go test -race ./...
go vet ./...
```

Automated tests use local HTTP fixtures and actual IMAP/SMTP socket connections.
They do not send real email. See [architecture](docs/architecture.md) and
[verification notes](docs/verification.md) for implementation boundaries and live
checks.
