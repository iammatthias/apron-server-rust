# Interop: expected failures

`tools/interop/run.sh` runs apron-server-go's Playwright suites, which encode
the Go server's behavior. Where this server follows apron-server-cloudflare
instead (docs/DEVIATIONS.md), those tests fail by design. The shim
(`bin/go`) turns off what is configurable, such as the limits, status
coalescing and read-only guests. The tests below still fail, and they are the
expected result.

Last full run: 2026-10-29, at 09a99cd (a retired guest's thread stays): 32
passed, 12 failed, all of them listed here. The run before, 2026-10-28
after Track E (E1 to E9), was 30 passed and 14 failed.

The last three rows, the `reference.spec.ts` tests at :241, :167 and :198,
were traced on 2026-10-29 rather than inferred: each was run with
`tools/interop/run.sh --project=desktop <spec>:<line>`, its Playwright
error context read, and the server's frames replayed with a scripted
WebSocket client. Their function names are where each side decides.

| Test | Why it fails |
|---|---|
| `chat.spec.ts:421` shows who joined as a quiet line | Guests are named `Guest <n>` and their requested name is ignored, as on Cloudflare (DEVIATIONS.md, Guests). The test expects `guest_<n> joined`. |
| `chat.spec.ts:790` mentions someone by name or user_id | The test signs in a guest with a name of its own and looks for it in the profile button. The server names it `Guest <n>`. |
| `chat.spec.ts:952` turns the jump bar rust when a mention lands above the fold | The same requested guest name. |
| `chat.spec.ts:1057` inserts an emoji at the composer caret | The same: the mention chip shows `Guest <n>`, which has a space, where the test expects one word. |
| `reference.spec.ts:279` marks where you stopped reading | The same requested guest name. |
| `reference.spec.ts:63` sends images and files as uploads | A `.txt` file is not an upload type. Cloudflare takes images and audio only, and `ext:media` tells the client, which refuses the file before staging it (DEVIATIONS.md, Uploads and `ext:media`). |
| `webauthn.spec.ts:58` passkeys preserve identity | A guest that registers a passkey becomes a new `u_` account, as on Cloudflare. It does not keep its `guest_<n>` user_id (DEVIATIONS.md, Account user_ids from a guest's passkey registration). |
| `webauthn.spec.ts:115` a rejected passkey verification leaves the guest usable | The same user_id rule. |
| `push.spec.ts:257` web push delivery | A delivery to a host that closed its idle keep-alive connection is lost. This is the rust-stdlib transport gap in docs/PORT.md, "Pending rust-stdlib fixes". It is not caused by a protocol choice. |
| `reference.spec.ts:241` leaves and rejoins rooms and threads | The guest that started the thread is its only member and leaves it with `room_leave`. The server answers `room_update` `left` and `{}`, and the thread is gone: a `room_list` with `parent_room_id: "general"` lists it in neither array, so the client renders no card at reference.spec.ts:254. That is `leave_locked` calling `remove_if_empty_locked` (src/server/rooms.rs), as Cloudflare's `handleRoomLeave` calls `removeIfEmpty` and `Store.removeEmptyThread` (src/index.ts, src/store.ts; SPEC.md: a thread is removed "when a leave ... leaves nobody in it, whatever messages it holds"). Go keeps an empty thread. |
| `reference.spec.ts:167` uploads an avatar | The test's user is a guest. The profile dialog's avatar input sends `command` `/avatar` with one upload embed, and the server answers `denied`, `Sign in with a passkey to use /avatar` (`Audience::Accounts` in src/server/commands.rs), as Cloudflare's `COMMANDS` entry for `avatar` has audience `owners` and its command dispatch refuses a guest with the same message (src/index.ts). No `user` frame follows, so the earlier message shows no avatar at reference.spec.ts:182. |
| `reference.spec.ts:198` runs commands from the composer | A guest's `/help` notice is one line, ``- `/help`: list the commands you can use here``, in the DOM and on the wire. `help_command` lists what `Audience::lists` allows the sender (src/server/commands.rs), as Cloudflare's help filters `COMMANDS` to `everyone`, plus `owners` for registered users and all for admins (src/index.ts). The test waits for a notice containing `/avatar` at reference.spec.ts:207, which a guest never gets. |

A test that fails and is not in this table is a regression.
