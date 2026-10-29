# Interop: expected failures

`tools/interop/run.sh` runs apron-server-go's Playwright suites, which encode
the Go server's behavior. Where this server follows apron-server-cloudflare
instead (docs/DEVIATIONS.md), those tests fail by design. The shim
(`bin/go`) turns off what is configurable, such as the limits, status
coalescing and read-only guests. The tests below still fail, and they are the
expected result.

Last full run: 2026-10-28, after Track E (E1 to E9): 30 passed, 14 failed,
all of them listed here. The five tests marked "before Track E" failed in
the same way at 2d60b94, with `--guest.posting` and `--push.hosts=*` added
to that commit's shim.

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
| `chat.spec.ts:313` starts threads from messages with replies (before Track E) | The thread card the test opens is not shown. Inferred cause, not traced: Cloudflare's thread rules (Rooms and threads in DEVIATIONS.md). |
| `chat.spec.ts:587` starts a thread, keeps drafts per room (before Track E) | The same thread card. |
| `reference.spec.ts:241` leaves and rejoins rooms and threads (before Track E) | After its only member leaves, the thread is removed, as on Cloudflare, so its card goes too. This is inferred, not traced. |
| `reference.spec.ts:167` uploads an avatar (before Track E) | Only an account may use `/avatar`, as on Cloudflare, and the test uses a guest. |
| `reference.spec.ts:198` runs commands from the composer (before Track E) | The test expects a guest's `/help` to list `/avatar`. A guest's help lists only the commands a guest can run. This is inferred, not traced. |

A test that fails and is not in this table is a regression.
