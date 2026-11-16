# Architecture

```text
Mail client
  ├── IMAP ── protocol/session views ─┐
  └── SMTP ── submission handling ───┤
                                    ├── Dooray provider ── HTTP web API
                                    └── KAIST session ──── HTTP SAML + email MFA
                                          │
                               private local cookie file

IMAP state ── embedded bbolt database (UIDs, flags, subscriptions, MIME cache)
```

`internal/model` defines the provider contract. `internal/bridge` implements
IMAP/SMTP through the emersion libraries. `internal/dooray` translates operations
to webmail requests. `internal/session` owns HTTP authentication and renewal.
`cmd/dooray-mail-bridge` loads configuration and starts the listeners.

## Authentication

Protocol credentials are checked against the configured KAIST credentials before
any upstream request. A cached web session never authorizes a different password.
The bridge follows the tenant's SAML login path, encrypts the password using the
SSO page's challenge parameters, requests email verification, and submits a fresh
code. Cookies remain private local state. There is no browser process or
JavaScript execution in the service.

Concurrent operations share session recovery. Read requests can be retried after
an explicit authentication failure; mutation requests are not replayed after an
uncertain response. Failed authentication attempts have a cooldown.

## IMAP state

Dooray message IDs are mapped to monotonically increasing UIDs within each
mailbox. UIDVALIDITY and the next UID are persisted. A complete provider snapshot
is validated before replacing mailbox state, so a failed page fetch cannot
silently expunge existing local messages.

Each selected client keeps its own sequence-number view. Incoming changes are
reported through EXPUNGE, EXISTS and FLAGS responses at protocol-safe points.
Polling refreshes active mailboxes. Original MIME is loaded on demand and cached
without marking messages read.

## Writes and SMTP

Read/favorite flags use Dooray's metadata mutation requests. Copy and move target
the actual remote folder ID. IMAP deletion is staged locally and committed only
on EXPUNGE. APPEND uses Dooray's original-message import request and verifies the
inserted message ID instead of guessing from the newest mail.

SMTP parses the submitted MIME, validates the sender, derives delivery recipients
from the SMTP envelope, creates a Dooray draft, uploads attachments, updates the
draft, and submits it once. Envelope-only recipients are kept in BCC. A failure
after draft creation may leave an unsent draft for inspection. A failure after
submission has an uncertain delivery outcome and is never blindly retried.

## Runtime footprint

The service uses a single Go process, persistent HTTP connections, and one local
bbolt database. It does not depend on Chromium, Node.js, MongoDB, Redis, or an
external IMAP daemon. MIME processing uses bounded buffers; resource consumption
depends on the size and number of concurrent messages.
