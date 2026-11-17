# Verification

The automated suite uses synthetic messages and local fake HTTP providers. Live
checks are performed separately against configured accounts and never run in CI.

## Automated coverage

On 2026-11-17, all **48 top-level tests** passed under `go test -race -count=1
./...`. The explicitly opt-in live-login test was skipped by this normal suite.
`go vet ./...`, a static Linux build, and `govulncheck ./...` also passed; the
vulnerability check reported no findings.

- Protocol authentication and SMTP relay rejection.
- IMAP MIME/attachment fetches, read-state handling, search, persistent UID state,
  and concurrent mailbox views.
- Dooray request payloads, folder hierarchy, pagination, import identity, SMTP
  recipient mapping, Korean MIME decoding, and ambiguous-send handling.
- HTTP login/session handling, fresh verification codes, and private cookies.
- Direct IMAP verification over validated TLS, read-only/PEEK wire commands,
  pre-request UID filtering, Naver's zero UIDVALIDITY, counter regression,
  reconnects, cancellation, Korean MIME and exact message identity checks.
- One-use SAML handoff after the optional device-notice skip.
- Listener configuration and loopback-only plaintext restrictions.
- Metadata-only subject search without downloading unrelated MIME/attachments.

## Live verification

Completed on 2026-11-17 with a configured KAIST account and a separate Naver
account, using the running bridge and the connected mail MCP:

| Check | Observed result |
| --- | --- |
| HTTP login | ID/PW, email verification, optional device-notice skip, and SAML handoff completed without a browser or JavaScript runtime |
| Direct IMAP verification | With the code-service URL empty, the bridge read a fresh code from Naver over IMAP/TLS, completed KAIST login, and accessed six Dooray mailboxes; newly received verification mail remained unread |
| Session reuse | Service restart reused persisted cookies and reached the same account |
| IMAP receive | A Naver test mail was read from KAIST through the bridge |
| MIME/attachments | Downloaded binary attachment SHA-256 matched the original |
| Read state | PEEK preserved unread state; normal FETCH marked read; read/unread and favorite changes were visible in a second session |
| Mailbox operations | CREATE, RENAME, COPY, MOVE, staged deletion, EXPUNGE, and DELETE passed using temporary test folders |
| APPEND | Imported synthetic MIME was downloaded byte-for-byte unchanged; temporary imported mail was removed |
| SMTP delivery | A message submitted to the bridge arrived at Naver with Korean text and the expected attachment |
| PNG attachments and inline images | Ordinary PNG and HTML CID image were submitted over TLS SMTP; both Naver attachment downloads matched the source SHA-256, and the Sent-folder MIME contained the matching CID reference |
| Round trip | The file actually received at Naver was attached to a reply; the bridge retrieved it via IMAP and the hash still matched |
| UID persistence | Restart preserved the test message's UID and mailbox UIDVALIDITY |
| TLS | IMAP read and SMTP authentication passed over certificate-validated TLS connections; SMTP negotiated TLS 1.3 |
| Relay rejection | An unauthenticated SMTP MAIL command was rejected before any delivery |
| Docker Compose | The multi-stage image built and ran as UID 10001 with a read-only root filesystem and persistent data volume on Docker 20.10 / Compose 2.9; direct IMAP verification succeeded from the container |
| Public deployment | From outside the server LAN, both forwarded ports negotiated certificate-validated TLS 1.3; IMAP login, read-only INBOX access, SMTP authentication and unauthenticated-relay rejection passed |
| Certificate renewal helper | A synthetic certificate was copied, unchanged files caused no restart, and a mismatched replacement key was rejected before changing the installed pair |

The synthetic mail subjects identify them as bridge tests. Original unrelated
mail was not modified. All temporary test folders and their copied/imported
messages were removed; the delivered test conversations remain in the accounts.

A stripped, static Linux/amd64 build including direct IMAP support was 10,240,160
bytes. One earlier RSS sample after
restart and the TLS checks was 16,376 KiB. This is a local observation, not a
memory ceiling; large MIME messages and concurrent clients increase usage.

## Unverified or unsupported behavior

Draft APPEND to the system Drafts mailbox is supported. Regression tests cover
exact MIME import, read/favorite flags, draft replacement, unsent drafts without
recipients, and UID/body/attachment persistence after restarting the bridge.
Changes to `\Answered`/`\Draft` through STORE, arbitrary SMTP header preservation,
UIDPLUS, and COPY of bridge-only imported-date/deleted overlays are not claimed.
Automatic expiry recovery was exercised with fake HTTP sessions; real fresh
login and real persisted-session reuse were verified separately.

No credentials, cookies, original mailbox content, or private test artifacts are
published with this report.
