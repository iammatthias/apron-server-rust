# Deviations

This file lists every known way a client can tell this server from
apron-server-cloudflare, the reference: its `SPEC.md` and its behavior,
with its defaults. Each section names the server it compares against.

- [Deviations from apron-server-cloudflare](#deviations-from-apron-server-cloudflare)
  lists where both servers do the same job and this one does it
  differently.
- [Extensions and choices where Cloudflare is silent](#extensions-and-choices-where-cloudflare-is-silent)
  lists what apron-server-cloudflare does not have. apron-server-go is the
  fallback there, and its behavior is named where this server differs from
  it.

When this server matches apron-server-cloudflare in an area, delete that
section. A client-visible difference that is not listed here is a bug.

## Deviations from apron-server-cloudflare

### `server.agent`

**Reference.** apron-server-cloudflare sends `apron-cloudflare-demo/9`.

**This server.** Sends `apron-rust/9`.

**Why.** The agent names the implementation. Clients key nothing on it.
`apron` carries the protocol version.

### Display names (§3.3)

**Reference.** apron-server-cloudflare trims a name and refuses one longer
than 80 code points or 320 bytes with `too_large`. It does not normalize
the name.

**This server.** Drops Cc, Cf, Co and Cs characters, maps Zs to a space,
collapses and trims spaces, and cuts the name to 64 code points instead of
refusing it. It does not apply NFKC or the PRECIS FreeformClass check, so a
name with fullwidth letters is kept as sent.

**Why.** The cleanup follows the PRECIS Nickname profile (RFC 8266) that
apron-server-go applies. rust-stdlib has no Unicode normalization, and a
third-party crate needs the owner's approval. The Go test
`TestNamesAreNormalized` is ignored for this reason.

### Account user_ids from a guest's passkey registration (§3.2, §3.3.3)

**Reference.** apron-server-cloudflare gives a guest that registers a
passkey a new account, `<slug>_<4 digits>` or `u_<random>`, with an NFKD
slug of the requested name (auth.ts `userIdSlug`, `candidateUserIdFor`).
It keeps guest memberships out of the log, so the rooms see no guest
leaves.

**This server.** Picks the user_id the same way, with these differences:

- The slug skips NFKD, so `Zoë Ångström` gives `zo_ngstr_m` here and
  `zoe_angstrom` on Cloudflare. A fullwidth letter is a separator.
- The slug also refuses `user`, the prefix of email accounts.
- The taken check ignores case and covers room names and `--role` holders.
  A renamed or purged user_id stays in `used_ids`, so it is taken too.
- A name over 64 code points is cut, not refused with `too_large`.
- The guest's leaves are logged and go to the rooms' other members before
  the account's joins, each join with the account's status. Everyone in
  those rooms then gets `user` `{new, old}`.
- A passkey added to an existing account names the user in the creation
  options as apron-server-go does. Cloudflare's `user.name` is the
  account's user_id.
- What a Cloudflare guest cannot hold (mutes, pushes, avatar) stays with the
  retired guest.

Accounts made before 2026-10-28 keep `guest_<n>` user_ids until an admin
moves them with `/rename` (docs/PORT.md, Migrating a guest_<n> account).

**Why.** The owner chose Cloudflare's user_ids on 2026-10-28. The
differences come from logging guest memberships and from the missing
Unicode normalization. Two Go Playwright tests fail by design
(`tools/interop/expected-failures.md`).

### Guests (§3.2, §3.3)

**Reference.** apron-server-cloudflare denies a read-only guest's writes
with `Guests can only read here; sign in with a passkey to post or join
rooms`, and a guest's `me` with `ext` with `Only registered users keep
ext`.

**This server.** Says `Guests can only read here; sign in to post or join
rooms` and `Only registered users may change their profile`. The switch is
`--guest.posting` (`[guest] posting = true`) instead of `GUEST_POSTING`. A
malformed requested `user_id` is still `invalid_params`.

**Why.** The texts predate the reference.

### Passkey attestation formats

**Reference.** apron-server-cloudflare verifies registrations with
`@simplewebauthn/server`, which verifies every attestation format that
library supports.

**This server.** Verifies `none` and `packed` self attestation only. The
other formats fail with `Passkey verification failed`.

**Why.** Both servers request no attestation (`attestationType: "none"`),
so a conforming client sends `none` or self attestation. Porting the X.509,
TPM and SafetyNet checks would serve only clients that ignore the
preference (docs/PORT.md).

### `/passkeys` on older passkeys

**Reference.** apron-server-cloudflare always knows when a passkey was
added and last used.

**This server.** Shows `unknown` for both days of a passkey stored before
these times were kept.

**Why.** The times did not exist when those passkeys were stored.

### Admin token (§3.2), `--admin-token-file`

**Reference.** apron-server-cloudflare reads the Worker secret
`APRON_ADMIN_TOKEN`.

**This server.** Reads the token at start from the file
`--admin-token-file` names, else from `$APRON_ADMIN_TOKEN`, without
surrounding whitespace. A token shorter than 16 bytes stops the server.
Only its SHA-256 is kept. If the store already holds a different user
`admin`, made before the user_id was reserved, the token fails with
`internal_error`.

**Why.** A file keeps the token out of `--print-config`. The length check
guards a token anyone on the internet may try.

### `/invite-token` (§4.1, §3.2)

**Reference.** apron-server-cloudflare's notice links to the URL the
connection reached.

**This server.** Links to the `/ws` endpoint under `--public-url`, or the
first `--tls.domain`. Without one, the notice has no link line. A user_id
that `--role` grants is free for `/invite-token`, and the new account gets
the granted roles.

**Why.** This server builds links one way for every command, from
configuration and not from the request's `Host`, so it never links to an
address it may not be reachable at.

### `/invite` and `server.signup` (§3.2, §4.1, Appendix B)

**Reference.** apron-server-cloudflare lists `signup` as `webauthn` and
`token`, refuses a sign-up `name` over the limit with `too_large`, and
reserves storage budget before each sign-up.

**This server.** `signup` lists `webauthn` where passkeys are offered,
`email` where email sign-in is on, and always `token`. A long `name` is cut.
The link follows `--public-url`, as for `/invite-token`. `server.welcome`
does not mention invite tokens. There is no storage budget.

**Why.** Email sign-in exists only here. A sign-up runs as one step under
the state lock, so uses never exceed the count without a budget.

### `/invite-device` (§4.1, §3.2)

**Reference.** apron-server-cloudflare closes a replaced token's
connections with close code 1008 and deletes all of the account's push
registrations. Its link names the URL the connection reached. A
connection already signed in that presents a device token is `denied`.

**This server.** Closes them as described in
[Closing a connection](#closing-a-connection). The link follows
`--public-url`, as for `/invite-token`. A connection already signed in
may present a device token, which switches it as a session token would.
A replacement deletes only the push registrations made under the old
token. A registration stored before the server recorded the token is kept.

**Why.** A native client (the iOS app Ladle) signs in with these tokens.
Keeping the account's other devices' registrations keeps their pushes
working.

### `/invite-bot` and bot users (§4.1, §3.2, §3.3)

**Reference.** apron-server-cloudflare counts a new bot against its
registration limits, ends the token notice with a `Say hello when you join`
line, closes a replaced token's connections with 1008, and makes a second
bot, `bot_<new>`, for an owner renamed with `/rename`.

**This server.**

- No registration limits (see
  [Registration limits](#registration-limits-spec-6)). One bot per account
  bounds the bots.
- No `Say hello` line, so bots do not greet rooms.
- A replaced token's connections close as described in
  [Closing a connection](#closing-a-connection).
- The `Connect to` line names the `/ws` endpoint under `--public-url`, and
  reads `Connect to this server's WebSocket URL` without one.
- A bot belongs to its owner by an owner field, not by its name, so it
  keeps `bot_<old>` after a rename. A later `/invite-bot` gives that bot a
  new token.
- If `bot_<owner>` is held by someone else, a user_id taken before the
  prefix was reserved, `/invite-bot` is `denied`.

**Why.** Finding bots by owner means a purge after a rename cannot leave a
bot whose token still signs in.

### Idle bot sweep (§3.2)

**Reference.** apron-server-cloudflare runs the sweep from its alarm at most
daily and closes a swept bot's connections with 1008.

**This server.** Runs it from the hourly maintenance thread. A swept bot's
connections get a connection-level `denied` error (`Signed out after a week
without signing in or posting`) and close. Its push registrations go too. A
bot stored before activity was kept counts as active from the first start
that keeps it.

**Why.** The hourly thread already exists. The close follows
[Closing a connection](#closing-a-connection).

### Closing a connection

**Reference.** apron-server-cloudflare closes a revoked, purged or swept
connection with WebSocket close code 1008 and a reason.

**This server.** Queues a connection-level error frame (no `id`, code
`denied`, the reason as its message) and then closes the TCP connection
without a close frame. Policy closes (frame rate, repeated violations,
authentication timeout) still use close code 1008. As on Cloudflare, the
server runs no frame the connection sends after the error is queued.

**Why.** The error frame tells the client why in the protocol. A close
handshake would wait on a peer that may not be reading, behind up to 128
queued batches.

### Liveness (§1; SPEC §3, Socket lifecycle)

**Reference.** apron-server-cloudflare advertises `server.ping` as 45
seconds and closes a connection that pinged and then sent nothing for 150
seconds. It cannot send WebSocket pings.

**This server.** Advertises 30 seconds and closes a connection that pinged
and then sent nothing for three intervals and the 10-second WebSocket ping
timeout, 100 seconds. It also sends WebSocket pings every interval and
closes a connection that misses a pong. A connection that never pings is
closed after 15 minutes without a frame, after the same `~private` notice
as Cloudflare's, and both closes use 1001 as Cloudflare's do.

**Why.** The interval and timeouts are Go's defaults, kept from the port.
WebSocket pings find a vanished peer that the protocol ping alone would
miss.

### Roles (§3.3), `--role`

**Reference.** apron-server-cloudflare stores roles with the identity and
changes them only with `/admin` and `/role`.

**This server.** Also seeds roles from `--role role=user_id` or
`role=email`. Each grant is given once, when the server starts or the
account is made, and the grants given are remembered, so a role an admin
took away does not come back at the next restart. `--role moderator=…`
grants `mod`. A malformed role name stops the server.

**Why.** `--role` predates the reference.

### `/admin`, `/role`, `/kick` and `/help` (§4.1, §3.3)

**Reference.** apron-server-cloudflare's `/help` lists `/invite-bot`,
`/invite-device`, `/avatar`, `/passkeys`, `/admin`, `/role`, `/kick`, then
the other admin commands. Its `/role` line names `threader` and says any
role raises posting limits.

**This server.**

- `/help` lists `/avatar`, `/invite-device`, `/invite-bot`, `/passkeys`,
  `/kick`, `/admin`, `/role`, then the other admin commands, with its own
  texts for `/avatar` and `/invite-bot`.
- The `/role` line names `admin`, `mod`, `bot` and `friend`, and leaves out
  `threader` and posting limits.
- A user with an email address cannot be made a bot (`denied`, `A bot signs
  in with a token and holds no email address; this user has one`).

**Why.** The earlier commands kept their order and texts. Email addresses
exist only here.

### `/rename` (§4.1, §3.3)

**Reference.** apron-server-cloudflare refuses the renamed user's sessions
when they are presented, and makes a second bot for the new user_id.

**This server.**

- Deletes the user's sessions at once. A client sees the same `Session
  expired; sign in again`.
- Keeps the old user_id in `used_ids`, which also takes it from
  `/invite-token` and passkey registration, ignoring case.
- Frees a user_id that `--role` grants, and the renamed user then gets the
  granted roles.
- Moves the email sign-in address and pending email proposals.
- Keeps timed mutes running under the new id.
- Keeps the bot as `bot_<old>` with its token, owned by the new id (see
  [`/invite-bot`](#invite-bot-and-bot-users-41-32-33)).

**Why.** Sessions are found by user here, so deleting them is one step.
The bot follows its owner so that `/purge <new>` removes it.

### `/purge` (§4.1)

**Reference.** apron-server-cloudflare closes the user's connections with
1008 `Removed by an admin` and counts uploads in its reply.

**This server.**

- Closes them as described in
  [Closing a connection](#closing-a-connection), with the message
  `Removed by an admin`.
- Deletes the user's sessions at once, so a resume is `denied` as on
  Cloudflare.
- Keeps the user_id in `used_ids`.
- Leaves link previews and streams out of the upload count.
- Removes the user's email sign-in address and pending proposals.
- Recounts unread messages for everyone, as retention does.
- Removes every bot the user owns, found by owner and not by the name
  `bot_<user_id>`, so a renamed user's bot goes too. A user who only holds
  the name `bot_<user_id>` stays.

**Why.** Finding bots by owner means a purge after a rename cannot leave a
bot whose token still signs in. The live check (`tools/deploy/live-check.mjs`)
uses `/purge` to remove its `livecheck_` accounts.

### `/toggle` (§4.1, §4.5, §4.7, §4.8)

**Reference.** apron-server-cloudflare offers `/toggle uploads` only with
uploads configured and `/toggle presence` only with push configured.

**This server.** Always offers both, because it always takes uploads and
always offers `status`. Turning presence on sends each user's shown status
to those who share a room with them as `user` `new`.

**Why.** The features exist in every configuration here.

### `/server` and `server.title`, `description` and `avatar` (§3.1, §4.1)

**Reference.** apron-server-cloudflare sets the defaults with
`SERVER_TITLE`, `SERVER_DESCRIPTION` and `SERVER_AVATAR`, limits the title
to 80 code points, and stores the avatar under `e/` on its media origin.

**This server.** Takes the defaults from `--server.title`,
`--server.description` and `--server.avatar` (`[server]` in TOML) and
names those flags in its notices. The title limit is 64 code points. The
avatar is an upload served from `/files/` on this server's origin with the
same cache header. With uploads off, `/server avatar` is refused as
`/avatar` is, and it counts as an upload as `/avatar` does.

**Why.** Names here are at most 64 code points. aprond serves its own
uploads.

### Custom emoji and `/emoji` (EXTENSIONS.md `ext:emoji`)

**Reference.** apron-server-cloudflare publishes the catalog to its media
bucket at `e/c/<SHA-256>.json`. A new key whose write finishes after the
catalog filled fails with 410, saying the upload is no longer wanted. It
applies a write that finishes after its sender lost the role.

**This server.**

- Serves the catalog at `/emoji/<SHA-256>.json` on the connection's base
  URL (`--public-url` where set), and the images from `/files/` with the
  same cache header.
- The 410 says `This server keeps at most <n> custom emoji; remove one
  first`.
- `/emoji remove :name:` also drops every add of that key still on its way,
  whose write URL then answers 404.
- A write that finishes after its sender lost every one of the roles fails
  with 403 (`/emoji needs one of the roles admin, mod, friend`).
- With uploads off, `/emoji add` is refused with `Uploads are turned off
  here`, and it counts as an upload (see
  [`ext:limits`](#extlimits-extensionsmd-spec-6)).
- The limits are not flags.

**Why.** aprond serves its own uploads. A removal or a role taken away is
final, not undone by an image already on its way.

### Rooms and threads (§4.2.4)

**Reference.** apron-server-cloudflare refuses a nested thread with
`Threads cannot be nested on this demo`. A private room has no threads. An
untitled thread is `Thread`. A guest's departure removes nothing.

**This server.**

- Says `Threads cannot be nested`.
- A private room may have threads, private or not, which count against the
  100 public rooms. No message moves into or out of a private room, its
  threads or a private thread.
- An untitled thread takes the first line of its description, else
  `Thread`.
- A guest's retirement (its last connection closed, its connection signed
  in as someone else, or a restart) logs its leaves but removes no thread
  they empty. The thread stays in `not_joined` until someone leaves it or
  its log expires.

**Why.** Private threads and titles from descriptions predate the
reference, and apron-web shows them. A page reload in apron-web closes the
guest's connection and signs in a new guest, so removing the thread then
would take its card away from everyone.

### Memberships of others (§4.2.2)

**Reference.** apron-server-cloudflare lets an allowed user add someone to
a room they have not joined.

**This server.** The adder must have joined the room (`Join <title> before
adding others to it`). Adding someone to a private room's thread takes
adding them to the room first.

**Why.** Private threads exist only here. The join rule predates the
reference.

### Reaction entries (§4.7)

**Reference.** apron-server-cloudflare qualifies emoji with the runtime's
`\p{RGI_Emoji}` (emoji.ts `qualifyEmoji`) and does not rewrite stored
sets.

**This server.** Qualifies from a table of the fully qualified sequences
that hold U+FE0F, generated from Unicode's `emoji-test.txt` by
`tools/emoji/generate.mjs` into `src/server/emoji_qualified.txt` (Unicode
18.0). It agrees with Cloudflare's function on all 5,244 sequences of that
file under Node 22. Reaction sets stored before this load qualified and are
saved so. Records logged before 2026-10-29 keep the form they were sent in,
so `history` may return one unqualified (docs/PORT.md, 2026-10-29).

**Why.** A table keeps the result independent of the runtime's Unicode
data. The log is append-only, so old records are not rewritten. Clients
compare entries without U+FE0F (§4.7).

### `server.welcome` and the welcome notice (§3.2, §3.5)

**Reference.** apron-server-cloudflare's `welcome` is `general`'s
description, else a generated summary. Its notice gives the deploy tag.

**This server.**

- `--welcome` (`welcome` in TOML), when set, comes before `general`'s
  description.
- The notice gives the crate version.
- The summary names email sign-in when it is configured, and retention
  only when `--history.retention` is set.
- On a connection not offered passkeys, the summary says where they work,
  and the notice points at email or says only `Guests can read.`.
- A connection refused for capacity gets no notice.

**Why.** `--welcome` predates the reference and keeps a deployment's text
fixed. A Rust build has no deploy tag.

### History retention (§4.2, §4.3.3), `--history.retention`

**Reference.** apron-server-cloudflare always keeps rolling history: 7
days, cleaned daily, on Workers Paid. It expires by a commit time kept
apart from `log_id`, tells only a removed thread's members, and deletes
uploads through bucket lifecycle rules (7 days for attachments, 30 for
avatars).

**This server.**

- Keeps everything by default. `--history.retention <duration>`
  (`[history] retention = "168h"`, Go duration syntax) turns retention on.
  An empty or `0` value keeps everything. A negative or unparsable value
  stops the server.
- Expires by `log_id`, which is the commit time in milliseconds or later,
  in the hourly sweep and at every start. The floor is stored as
  `history_floor` and never decreases.
- A removed thread or private room goes to everyone who could see it as
  `room_update` `left`.
- A private room with live threads waits for them.
- A message's files go with the message. Avatars and accounts never
  expire.
- A `room_list` delta from before the latest removal gets a full listing,
  since a delta cannot name a removed room.

**Why.** A self-hosted server may want to keep everything, so retention is
opt-in. `log_id` already carries the commit time here.

### History pages (§4.3; SPEC §6, Payload and query bounds), `--limit.*history*`

**Reference.** apron-server-cloudflare refuses a second page in flight on
one connection with `History request already in progress`.

**This server.** Has the same sizes and limits by default, as flags (0 is
unlimited). It has no in-flight refusal.

**Why.** A connection's frames run one at a time, each to completion, so a
second page can never be in flight.

### Uploads and `ext:media` (EXTENSIONS.md, §4.8)

**Reference.** apron-server-cloudflare's types and sizes are fixed by its
plan, and `ext.media.origins` names its media bucket. It refuses an
attachment's declared type before the body and leaves the write open.

**This server.**

- `--upload.max-mb` (default 5), `--upload.max-avatar-kb` (default 256)
  and `--upload.type` (repeatable, a MIME type, `type/*` or `*/*`) change
  them. A type the sniffer does not know is taken from its declared type.
- No `origins`: uploads are served from this server's own origin.
- An attachment's declared type is checked once the body is read, and a
  refusal fails the write. Avatar, custom emoji and server avatar writes
  are refused before the body, as on Cloudflare.

**Why.** A self-hosted server may want other sizes or files.

### `ext:permissions` (EXTENSIONS.md)

**Reference.** apron-server-cloudflare gives an owner's bot `write: false`
while guests only read.

**This server.** Gives an owner's bot `{}`.

**Why.** A bot writes on this server whether or not guests may.

### Frame and field sizes (§1, §1.1)

**Reference.** apron-server-cloudflare bounds frames at 16 KiB, JSON at 8
levels and 2048 values, request ids at 128 bytes and `body.text` at 4 KiB.
It also bounds message snapshots at 8 KiB, user `ext` at 512 bytes and room
fields at 2 KiB.

**This server.** Has the same frame, JSON, id and text bounds by default,
each a flag (`--frame.max-bytes`, `--frame.max-text-bytes`,
`--frame.max-depth`, `--frame.max-nodes`, `--frame.max-id-bytes`). It has
no snapshot bound. A message's `ext` is bounded at 64 KiB, and a profile's
`ext`, a room's `ext` and a room description at 16 KiB each. Only a raised
`--frame.max-bytes` reaches them.

**Why.** Cloudflare sizes its field bounds to its Durable Object budgets.
The frame bound already caps every field.

### Client address (SPEC §5, IP key), `--client-ip-header`

**Reference.** apron-server-cloudflare reads `CF-Connecting-IP` (with
`CF-Connecting-IPv6` for Pseudo IPv4), keys by IPv4 or the IPv6 /56, stores
the key hashed, and also limits a native IPv6 /48.

**This server.** Reads the last entry of the configured header, or the
connection's own address without one, and keys it the same way, unhashed.
With the header configured, a connection that lacks it is refused with 403
`Trusted client address unavailable`. There is no /48 limit and no Pseudo
IPv4 handling.

**Why.** The key lives only in memory, so it needs no hash. The server may
sit behind any proxy.

### Connection caps (SPEC §6, Connections)

**Reference.** apron-server-cloudflare refuses a connection past its caps
before the upgrade with HTTP 429 and `Retry-After`, and has a daily
admission budget of 4,000.

**This server.** Has the same caps and admission rate by default, each a
flag (`--max-connections`, `--limit.*connections*`,
`--limit.admissions-per-ip-minute`, 0 is unlimited). A refused connection
is upgraded, gets its `server` frame and a `retry_after` error without
`id`, and is closed. The connection-status probe answers 429 with
`Retry-After` for the caps. An account past its cap gets `retry_after` for
its `auth`. There is no daily admission budget.

**Why.** A client sees the reason in the protocol instead of a failed
handshake. The daily budget guards Cloudflare's bill.

### Registration limits (SPEC §6)

**Reference.** apron-server-cloudflare counts each new account, bot and
added passkey as a registration: 5 a UTC day per IP key and 300 a day for
the server. Past either, the request is `retry_after` with `Registration
limit reached for this network` or `Registration limit reached` until the
day ends. A new account or bot past 10,000 identities is `denied` with
`registration_closed`.

**This server.** Has no registration limits. Passkey registration, email
sign-in, `/invite-token`, `/invite` sign-ups and `/invite-bot` make
accounts without a count.

**Why.** Cloudflare's counts bound the rows sign-ups write against its
storage budget, and this server has no storage budget (see
[Budget stops](#budget-stops-storage-failures-and-admin-alerts-spec-6)).

### Posting limits (SPEC §6, Posting), `--limit.*posts*`

**Reference.** apron-server-cloudflare keeps its limiter rows in SQLite, so
a restart keeps them.

**This server.** Has the same posts, tiers, defaults and messages, each a
flag (0 is unlimited). The rows live in memory, so a restart starts every
poster's minute and day afresh.

**Why.** Durable counts guard Cloudflare's bill across evictions. A
self-hosted server restarts rarely.

### `ext:limits` (EXTENSIONS.md, SPEC §6)

**Reference.** apron-server-cloudflare refuses an upload when its store is
full, with the `upload` category.

**This server.** Evicts the oldest uploads instead, so a full store names
no category. `/server avatar` counts as an upload. The limits are flags
(`--limit.room-lists-per-minute`, `--limit.uploads-per-*`, 0 is
unlimited).

**Why.** Eviction is this server's storage cap (see
[Uploads](#uploads-and-extmedia-extensionsmd-48)).

### Frame limits and policy violations (SPEC §4, §6)

**Reference.** apron-server-cloudflare reserves IP frames in leases of 10,
has a daily frame budget and a bound of 8 pending frames or 128 KiB, and
refuses a request at the server-wide limit with `Demo is busy with too many
requests`.

**This server.** Has the same limits and close codes by default (600
server-wide, Cloudflare's Paid number), each a flag (`--limit.frames-*`,
`--limit.server-frames-per-minute`, `--limit.policy-violations`, 0 is
unlimited). The refusal says `Server is busy with too many requests`. There
are no leases, no daily budget and no pending-frame bound. A binary frame
closes with 1003 `text frames required`, and a frame over the size limit
closes with 1009 `read limited at <n> bytes`. Cloudflare's reasons are
`Binary application frames are not supported` and `Frame exceeds the
maximum size`.

**Why.** A connection's frames are read one at a time and each runs to
completion, so at most one is pending. Leases and the daily budget save
Cloudflare's SQL writes.

### Budget stops, storage failures and admin alerts (SPEC §6)

**Reference.** apron-server-cloudflare closes when its budget guard or
flood trip turns on Cloudflare's edge stop, or when an operation overruns
its storage reservation. Either posts a message in `general` as the
`admin` user that mentions every admin, pushed at once past the usual
wait, coalescing and allowances. A failed budget read or write refuses
work with `Server storage is unavailable; try again shortly` until storage
works again. Every 503 for a failure or overload carries `Retry-After`,
60 seconds unless it has its own.

**This server.** Has no edge stop, flood trip, daily budget or storage
accounting, so it never closes for these reasons and posts no alert. A
failed store write is logged and the server keeps serving from memory. The
writer keeps the failed entries and writes them again, merged with any
later changes, with the next batch or after a backoff of 100 ms doubling
to 30 seconds. Shutdown makes a last attempt and logs what is still
unwritten. Its only 503 is while shutting down, without `Retry-After`.

**Why.** The stops and the accounting guard Cloudflare's bill. A
self-hosted server has no bill to stop, and its restart takes seconds, so
a 60-second retry would only delay clients.

### Request deduplication (§1.2; SPEC §8)

**Reference.** apron-server-cloudflare keeps every accepted mutating
request with its result for 24 hours in SQLite, keyed by user and request
id, with a SHA-256 of its method and canonical params. It keeps a guest's
requests the same way.

**This server.** Keeps the same key, hash and result. It stores an
account's entries as `dedup` store entries, so a retry after a restart
replays the result. A guest's entries stay only in memory, since its
identity ends with its connections. At most 1,024 entries a user are kept,
and past that the oldest go early.

**Why.** The bound keeps a flooding client's ids from growing the store
without end.

### Status announcements (§4.5; SPEC §4.4)

**Reference.** apron-server-cloudflare writes `seen` at most once per 10
minutes.

**This server.** Has the same coalescing and grace by default, each a flag
of 0 to 60 seconds (`--limit.status-coalesce-seconds`,
`--limit.offline-grace-seconds`). `seen` is exact.

**Why.** Cloudflare's granularity saves its SQL writes. The protocol has
`seen` exact.

### Push registration (§4.9)

**Reference.** apron-server-cloudflare allows 10 `push_register` requests a
user in any 60 seconds. It refuses a `wake` of more than 16 names with
`denied` and a name over 64 characters with `too_large`. It refuses a `url`
that carries credentials or a port, an IP address, a single-label host, or
a host under an internal suffix such as `.local` or `.internal`. Its texts
include `Unknown push kind; this server offers webpush`, `url is at most
512 bytes`, `push_id must be 1 to 64 letters, digits, _ or -`, `url must be
an https URL` and `url must name a public push service`.

**This server.** Has the same numbers: 5 registrations a user, expiry after
7 days, URLs of at most 512 bytes, and 10 requests a minute. These differ:

- The 10 requests are a bucket that refills one every 6 seconds, so a user
  can make about 20 in the first minute. `retry_after` names the wait for
  the next one.
- A `wake` past 16 names, or a name past 64 bytes, is not refused. The
  extra names are ignored.
- A `url` may name a port or a public IP address. Only credentials, a
  trailing dot, internal address literals and `localhost` are refused. With
  the default `--push.hosts`, only the port can reach a push.
- The texts differ. An unknown kind is `Unknown push kind "<kind>"; this
  server supports relay and webpush`. A long `url` is `url is at most 512
  bytes and token at most 4096`. A bad `push_id` is `push_id is 1 to 64
  letters, digits, _ or -`. A bad `url` is `url must be an absolute URL`,
  `url must use https`, `url must name a host without a trailing dot` or
  `url must name a public host`. A bad `keys.p256dh` is `keys.p256dh must
  be an uncompressed P-256 point in base64url` or `keys.p256dh is not a
  point on P-256`.

**Why.** The checks and texts are apron-server-go's, kept from the port.
The host list, not the
address checks, keeps pushes to the browsers' push services.

### Push wakes (§4.9)

**Reference.** apron-server-cloudflare holds a wake for any attended user,
keeps coalescing times in storage, holds wakes per connection, and has
daily allowances: 5,000 pushes for the server, 200 per sender and 100 per
recipient (20 for `joined`).

**This server.** Has the same order, bounds, wait (`--push.delay`, 0 to
60s, default 30s), edit and delete rules, drops, coalescing windows and
held wakes, with these differences:

- An edit that adds mentions wakes the users it adds.
- Only users who hold a registration when a message comes are considered.
- Coalescing times live in memory, so a restart forgets them.
- Held wakes are kept per user.
- No server, sender or recipient allowances. Each user gets at most 1,000
  pushes a UTC day, counting only those the endpoint accepted.

**Why.** The allowances bound a metered platform's spend. The per-user cap
already bounds a flood here.

### Push delivery (§4.9), *interim until the rust-stdlib transport fix*

**Reference.** apron-server-cloudflare, like any HTTP client that detects
a closed connection, delivers a push to a host that closed its idle
keep-alive connection.

**This server.** Reuses the closed connection. The POST fails with `EOF`,
and the push is dropped with status 0. The registration is kept.

**Why.** rust-stdlib's `net/http` transport passes a closed idle connection
as healthy (docs/PORT.md, Pending rust-stdlib fixes). Disabling
keep-alives here would work around a rust-stdlib bug, which AGENTS.md rules
out. The Go Playwright test `push.spec.ts:257` fails on it.

## Extensions and choices where Cloudflare is silent

apron-server-cloudflare has none of the features below. Where
apron-server-go has one, this server follows it unless the section says
otherwise.

### Email sign-in (§4.11)

**Reference.** apron-server-cloudflare has no email sign-in and never
advertises `email`. apron-server-go has it, sending codes through SMTP or
the log, and lets a new email account request any user_id.

**This server.** Follows apron-server-go, with two differences:

- `--email.sender http` POSTs each sign-in email as JSON, `{"from", "to",
  "subject", "text"}`, to `--email.http-url` with each
  `--email.http-header` (`Name: value`, repeatable), such as Cloudflare
  Email Service's REST API with `Authorization: Bearer <token>`. A 2xx
  status is a delivery. `from` is `--email.from`.
- A requested user_id starting `bot_`, ignoring case, is not honored. The
  account gets the next `user_<n>`, as for a requested `guest_` or `user_`
  id.

**Why.** A homelab with a mail API but no SMTP relay can still offer email
sign-in. `/invite-bot` names each bot `bot_<owner user_id>`, so no other
user may hold the prefix.

### `--apple.app-id` and `/.well-known/apple-app-site-association`

**Reference.** Neither apron-server-cloudflare nor apron-server-go serves
the path. apron-server-go's `--static-dir` cannot serve it, because it
refuses dot paths.

**This server.** `--apple.app-id <team ID>.<bundle ID>`, repeatable
(`[apple] app-id = [...]`), makes `GET` on the path answer
`application/json` with `{"webcredentials":{"apps":[...]}}`. Without the
flag the path is 404. A malformed ID stops the server with `invalid
--apple.app-id`.

**Why.** A native iOS app can use a domain's passkeys only if the domain
lists the app under `webcredentials` (docs/PORT.md, Passkeys for a native
iOS client).

### Link previews, `--unfurl.enable`

**Reference.** Neither apron-server-cloudflare nor apron-server-go
unfurls links. A message's URLs stay text.

**This server.** Off by default. With `--unfurl.enable` (`[unfurl] enable =
true`), a saved message whose text gains http or https URLs is posted as
before and then unfurled in the background:

- The server scans the first 8 KiB of the text for the first 32 distinct
  URLs, skipping Markdown code. It leaves out URLs the previous snapshot
  already had and URLs an embed already links, and takes the first 3.
- Each user gets 10 URLs a minute and the server 60. At most 16 messages
  unfurl at once.
- Each page is fetched with `GET` and a `User-Agent` naming aprond, within
  5 seconds per URL including DNS, at most 3 redirects, no proxy, and only
  to public addresses on ports 80 and 443. The address check runs on each
  dialed address, after each redirect too.
- Only `text/html` and `application/xhtml+xml` answers are read, at most
  512 KiB, as text. The preview comes from the `og:` meta tags, with
  `<title>` and the meta description as fallbacks.
- The `og:image` is kept only if it is declared `image/*`, is at most 2
  MiB, and has the header of a PNG, JPEG, GIF or WebP of at most 8192
  pixels a side and 40 megapixels. It is stored as an upload of the
  message.
- Results are cached in memory: a preview for an hour, a failure for 5
  minutes, at most 256 entries and 32 MiB of images.
- The message is republished once with a `link` embed per preview,
  `{"embed_id", "kind": "link", "url", "og": {...}}`, within the 32-embed
  limit. A `link` embed is server-hosted (§4.8.2). Its image counts toward
  `--upload.max-storage-mb` and is evicted before any user upload.
- A job is not persisted. A restart before it lands leaves the message
  without the preview.

**Why.** Clients load media only from the server's origin (§4.8.1), so a
link can show a preview only if the server hosts it. Unfurling makes the
server request any public URL a user names, which reveals its address and
spends its bandwidth, so the operator opts in.

### Read receipts, `--read-receipts`

**Reference.** apron-server-cloudflare sends an account's read cursor only
to its own other connections. apron-server-go sends read cursors to every
member of the room.

**This server.** Follows apron-server-cloudflare by default.
`--read-receipts` restores apron-server-go's read receipts: cursors go to
the room's members, the reader's own connections included, and every
member's kept cursor follows `room_list`.

**Why.** Read receipts are a privacy choice for the server's owner.

### Push kind `relay`, the `badge` scope and `unread` (§4.9)

**Reference.** apron-server-cloudflare has kind `webpush` only, no `badge`
scope and no `unread` count.

**This server.** Also takes kind `relay`, whose host must be in
`--push.hosts` like any other. `push.relay` is `{}`, `push.wake` also lists
`badge`, and every payload carries `unread`, the user's count of messages
after their read positions. A `badge` registration of kind `relay` gets a
low-urgency push without a message on each change of that count.
`--push.allow-insecure`, for tests only, admits `http` and internal
addresses, but not hosts the list leaves out.

**Why.** Native iOS pushes and badges (Ladle) go through an operator's
relay. Browsers ignore both.

### WebSocket close handshake

**Reference.** apron-server-go's `Close` sends a close frame and waits up
to 5 seconds for the peer's.

**This server.** Sends the close frame and closes the TCP connection at
once.

**Why.** The server sends a close code only when it ends a connection for
a policy breach or load, after which it reads nothing more. The peer still
receives the close code.

### `aprond --help` width

**Reference.** apron-server-go wraps help to the terminal's width, and to
80 columns when standard input is not a terminal.

**This server.** Always wraps at 80 columns.

**Why.** rust-stdlib has no terminal-size call, and this crate forbids
`unsafe`.

### TOML syntax errors

**Reference.** apron-server-go prints `Failed to load <path>: ` and
BurntSushi/toml's message.

**This server.** Prints `Failed to load <path>: toml: ` and the `toml`
crate's message. The exit status, `unknown setting` errors and `setting
"...": ...` errors match.

**Why.** The decoder is a different library.

### TOML dates in the config file

**Reference.** apron-server-go passes a date to the option as
`time.Time.String()`, such as `1979-05-27 07:32:00 +0000 UTC`.

**This server.** Passes its TOML text, such as `1979-05-27T07:32:00Z`.

**Why.** No option takes a date, so only a string option sees the
difference.

### `/debug/pprof/` and `/debug/vars`

**Reference.** apron-server-go serves Go's runtime profiles and the
`cmdline` and `memstats` variables.

**This server.** Serves the same routes from rust-stdlib. The index and
`cmdline` work. The runtime profiles, `profile` and `trace` answer that the
profile is not available, and `/debug/vars` has no `memstats`.

**Why.** Rust has no Go runtime to profile.

### ACME certificates for clients without ECDSA

**Reference.** apron-server-go's autocert issues an RSA certificate
(`<domain>+rsa`) for a ClientHello with no ECDSA support.

**This server.** Issues ECDSA P-256 only. A client without ECDSA fails the
handshake.

**Why.** The RSA path serves only clients with no ECDSA support at all.
rust-stdlib-crypto has RSA, so it can be added.

### Non-ASCII TLS server names

**Reference.** apron-server-go's autocert converts the SNI name with
`idna.Lookup.ToASCII`.

**This server.** Fails with `acme/autocert: server name contains invalid
character`.

**Why.** TLS carries A-labels (RFC 6066 §3), so a conforming client never
sends a non-ASCII name.

### ACME failure text

**Reference.** When no challenge type is left, apron-server-go's autocert
names the authorization and domain only.

**This server.** Adds ` (last: <the CA's error for the last challenge>)`.

**Why.** The CA's reason is what an operator needs in the log.

### ACME time bounds

**Reference.** apron-server-go bounds `GetCertificate` with one
five-minute context.

**This server.** Stops polling at a five-minute deadline, and each request
to the CA times out after 30 seconds.

**Why.** rust-stdlib's HTTP client takes a timeout, not a context.
