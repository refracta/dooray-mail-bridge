# Dooray web-mail adapter contract

This package uses the same-origin, authenticated web API at `/v2/wapi`.
It does not use Dooray's public API-key service. The transport owns login,
cookie persistence, request timeouts, and safe session recovery.

The request contracts below were recovered from shipped web-client JavaScript
on 2026-11-17. Static request construction establishes how the client calls the
server. Live checks on the same date additionally verified original MIME reads,
read/favorite flags, folder create/rename/delete, copy/move/permanent deletion,
original-message import, and SMTP submission with an ordinary binary attachment.
Downloaded attachment hashes matched in both directions between KAIST and a
separate mail provider. A later SMTP test verified both an ordinary PNG and an
inline/CID PNG: the recipient downloads matched the source hashes and the HTML
referenced the received image CID. Original-MIME import also accepts the system
Drafts folder and preserves unsent messages byte-for-byte.
No third-party bundles, mailbox contents, credentials, or cookies are included
in this repository.

| Operation | Method and path | Request body |
| --- | --- | --- |
| Identity | `GET /members/me` | — |
| Folder listing | `GET /mail-folders?type=system` or `type=user` | — |
| Message listing | `GET /mails?folderId=…&view=timeline&preview=false` | — |
| Original MIME | `GET /mails/{id}?type=raw` | — |
| Read / unread | `POST /mails/read`, `POST /mails/unread` | `{mailIdList: [id]}` |
| Favorite | `PUT /mails/{id}/annotations` | `{mailId: id, favorited: boolean}` |
| Move / copy | `POST /mails/move`, `POST /mails/copy` | `{mailIdList: […], targetFolderId: id}` |
| Permanent delete | `POST /mails/delete` | `{mailIdList: […]}` |
| Create folder path | `POST /mail-folders/create-path` | `[{name: path, order: 1}]` |
| Rename folder path | `POST /mail-folders/{id}/update-path` | `{name: path}` |
| Delete folder | `POST /mail-folders/{id}/delete-path` | `{folderId: id}` |
| Import original MIME | `POST /mail-folders/{id}/import-mail` | Multipart field `file`, filename ending in `.eml` |
| Create draft | `POST /mail-drafts` | `[form]` |
| Update draft | `PUT /mail-drafts/{id}` | `form` |
| Attach file | `POST /mail-drafts/{id}/files` | Multipart field `file` |
| Attach inline image | `POST /mail-drafts/{id}/files?inlinefile=true` | Multipart field `file` |
| Send draft | `POST /mails/send` | `{draftId: id}` |

JSON responses have `header.isSuccessful` and `header.resultCode`. Data lives
inside `result`, commonly under `result.content` or `result.contents`.
Message size is `mailSummary.mimeSize`; the adapter also accepts a top-level
`mimeSize` for compatibility. Read, replied, and draft status come from
`mailSummary.flags`; favorite status comes from `annotations.favorited`.

The normal rendered-message GET is deliberately not used: prior integration
observed it marking messages read. Raw MIME download returns the original
octets and preserves read state.

`Delete` means permanent deletion. The web client's ordinary delete action
instead calls move with `targetFolderName: "trash"`. IMAP `\Deleted` is a local
marker until the protocol layer calls `Delete` during EXPUNGE.

`SetFlags` accepts only `\Seen` and `\Flagged`. It does not clear replied or
draft metadata. The protocol layer exposes those as read-only flags and stores
the deletion marker locally. System folders cannot be renamed or deleted.
APPEND accepts `\Draft` for the system Drafts folder, where mailbox membership
supplies that flag. The import endpoint stores the original message; it does
not create or submit a web-composer draft via `/mail-drafts`.

For import responses without an inserted message ID, the adapter compares the
folder before and after import and matches downloaded MIME bytes. It refuses
to guess based on the newest message or subject. Import INTERNALDATE overrides
must be stored by the local synchronization layer; the observed import request
has no separate timestamp field. A failed post-import lookup can mean that the
import succeeded, so it must not be retried automatically.

SMTP submission translates decoded MIME into Dooray's draft form. It preserves
the subject, text or HTML body, recipient visibility, and ordinary attachments;
Dooray constructs the outgoing MIME and transport headers. Envelope-only
recipients become BCC, never visible To recipients. MIME/envelope From must
match the configured account, and `/members/me` confirms the live identity.
Inline images use the same draft-file URL form as the web composer. A failed
submission can leave an unsent draft for inspection; it never triggers an
automatic second send.

Draft creation returns an array containing the new `id` and `version`. The
update must include that returned version; the initial composer version `0`
must not be reused blindly after creation.

Source locations in the observed build:

- `48913.2c3b35290c21e2c3.js`: API modules `530252` (read), `104238`
  (unread), `684675` (favorite), `195366` (move), `279947` (copy), `371425`
  (delete), `25636` / `353909` / `581039` (folder mutations), `646483`
  (MIME import), `655797` (attachments), and `90610` (message reads).
- `39969.e0dd576d7c7ea179.js`: `347638` (draft form and submission),
  `969496` / `721569` (create/update version handling),
  `915675` / `798853` / `214094` (mutation payload construction), and
  `59935` / `379674` (ordinary and inline attachment handling).
- `11282.4daca027225d178e.js`: original-message import form, multipart
  field `file`.
- `18999.ee34dda1dcc6c5c1.js`: `148521`, including the named
  `AUTH_UNAUTHORIZED_ERROR` value `-24400100`. Fresh unauthenticated identity
  and folder requests were observed returning HTTP 401. HTTP 403 can represent
  ACL or content-policy rejection and is not treated as session expiry.

Private research evidence was retained outside the source tree. The selected
API-bundle REA record is
`ev_363c7af0120462b2b13f42fff0d9dc2e5322c06104bf43a936953cde013510e9`.
Its static graph has bounded alias analysis and does not claim complete
application or endpoint coverage.
