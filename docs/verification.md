# Verification

The automated suite uses synthetic messages and local fake HTTP providers. Live
checks are performed separately against configured accounts and never run in CI.

## Automated coverage

On 2026-11-17, all **42 top-level tests** passed under `go test -race -count=1
./...`. The explicitly opt-in live-login test was skipped by this normal suite.
`go vet ./...`, a static Linux build, and `govulncheck ./...` also passed; the
vulnerability check reported no findings.

- Protocol authentication and SMTP relay rejection.
- IMAP MIME/attachment fetches, read-state handling, search, persistent UID state,
  and concurrent mailbox views.
- Dooray request payloads, folder hierarchy, pagination, import identity, SMTP
  recipient mapping, Korean MIME decoding, and ambiguous-send handling.
- HTTP login/session handling, fresh verification codes, and private cookies.
- Listener configuration and loopback-only plaintext restrictions.
- Metadata-only subject search without downloading unrelated MIME/attachments.

## Live verification

Completed on 2026-11-17 with a configured KAIST account and a separate Naver
account, using the running bridge and the connected mail MCP:

| Check | Observed result |
| --- | --- |
| HTTP login | ID/PW, email verification, optional device-notice skip, and SAML handoff completed without a browser or JavaScript runtime |
| Session reuse | Service restart reused persisted cookies and reached the same account |
| IMAP receive | A Naver test mail was read from KAIST through the bridge |
| MIME/attachments | Downloaded binary attachment SHA-256 matched the original |
| Read state | PEEK preserved unread state; normal FETCH marked read; read/unread and favorite changes were visible in a second session |
| Mailbox operations | CREATE, RENAME, COPY, MOVE, staged deletion, EXPUNGE, and DELETE passed using temporary test folders |
| APPEND | Imported synthetic MIME was downloaded byte-for-byte unchanged; temporary imported mail was removed |
| SMTP delivery | A message submitted to the bridge arrived at Naver with Korean text and the expected attachment |
| Round trip | The file actually received at Naver was attached to a reply; the bridge retrieved it via IMAP and the hash still matched |
| UID persistence | Restart preserved the test message's UID and mailbox UIDVALIDITY |
| TLS | IMAP read and SMTP authentication passed over certificate-validated TLS connections; SMTP negotiated TLS 1.3 |
| Relay rejection | An unauthenticated SMTP MAIL command was rejected before any delivery |

The synthetic mail subjects identify them as bridge tests. Original unrelated
mail was not modified. All temporary test folders and their copied/imported
messages were removed; the delivered test conversations remain in the accounts.

A stripped, static Linux/amd64 build was 9,998,496 bytes. One RSS sample after
restart and the TLS checks was 16,376 KiB. This is a local observation, not a
memory ceiling; large MIME messages and concurrent clients increase usage.

## Unverified or unsupported behavior

Inline-image submission was unit-tested against the observed request contract,
but was not sent in a live test. Saving an IMAP draft with `APPEND \Draft` remains
unsupported. Changes to `\Answered`/`\Draft`, arbitrary SMTP header preservation,
UIDPLUS, and COPY of bridge-only imported-date/deleted overlays are not claimed.
Automatic expiry recovery was exercised with fake HTTP sessions; real fresh
login and real persisted-session reuse were verified separately.

No credentials, cookies, original mailbox content, or private test artifacts are
published with this report.
