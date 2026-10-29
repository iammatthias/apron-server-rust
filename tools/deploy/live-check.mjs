#!/usr/bin/env node
// Checks the deployed server over its public URL and prints PASS or FAIL per
// check, exiting 1 on any FAIL. Node 24; it uses the built-in WebSocket,
// which sends no Origin header.
//
//   node tools/deploy/live-check.mjs [--slow]
//
//   APRON_PUBLIC_URL        the server (default: https://apron.farfield.systems)
//   APRON_APP_ID            the app ID the AASA lists (default:
//                           MP92RCAPRG.app.ladle.ios)
//   APRON_ADMIN_TOKEN_FILE  a local file holding the admin token; without it
//                           the admin checks are skipped. The token is never
//                           printed.
//   --slow                  also waits out the 30 s authentication timeout
//
// It posts nothing in general or any public room. The admin checks make
// accounts named livecheck_<random>: one from /invite-token and one from a
// /invite sign-up. There is no /purge yet, so they stay until B8's /purge
// removes the livecheck_ accounts. The Track C checks post only in a
// private room named livecheck_<random> that the admin makes, and its
// thread; both go when the script empties them.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

const base = (process.env.APRON_PUBLIC_URL ?? "https://apron.farfield.systems").replace(/\/$/, "");
const wsURL = `${base.replace(/^http/, "ws")}/ws`;
const appID = process.env.APRON_APP_ID ?? "MP92RCAPRG.app.ladle.ios";
const slow = process.argv.includes("--slow");
const welcome = "Guests can read along. Create a passkey to post, react and start threads. Messages are kept for 7 days.";
const suffix = randomBytes(4).toString("hex");

let failed = 0;
function report(name, ok, detail = "") {
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${!ok && detail ? ` (${detail})` : ""}`);
}
async function check(name, fn) {
  try {
    const out = await fn();
    report(name, out === undefined || out === true, typeof out === "string" ? out : "");
  } catch (e) {
    report(name, false, e.message);
  }
}
const same = (got, want) => got === want || `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`;

// One WebSocket with every frame it received, in order.
class Conn {
  frames = [];
  closed = null;
  #waiters = [];
  #next = 1;
  constructor(url = wsURL) {
    this.ws = new WebSocket(url);
    this.ws.onmessage = (event) => {
      this.frames.push(JSON.parse(event.data));
      this.#wake();
    };
    this.ws.onclose = (event) => {
      this.closed = { code: event.code, reason: event.reason };
      this.#wake();
    };
    this.opened = new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = () => reject(new Error("connection failed"));
    });
  }
  #wake() {
    for (const w of this.#waiters.splice(0)) w();
  }
  async until(pred, ms = 8000, what = "a frame") {
    const end = Date.now() + ms;
    for (;;) {
      const found = pred();
      if (found) return found;
      if (this.closed) throw new Error(`closed ${this.closed.code} waiting for ${what}`);
      const left = end - Date.now();
      if (left <= 0) throw new Error(`timed out waiting for ${what}`);
      await new Promise((resolve) => {
        const t = setTimeout(resolve, left);
        this.#waiters.push(() => (clearTimeout(t), resolve()));
      });
    }
  }
  server() {
    return this.until(() => this.frames.find((f) => f.method === "server"), 8000, "the server frame");
  }
  // Sends a request and returns its reply and the frames that arrived since
  // the send, which hold a command's ~private notice.
  async call(method, params) {
    // The server keeps an account's request ids as idempotency keys, so a
    // rerun as the same admin needs ids no earlier run used.
    const id = `lc-${suffix}-${this.#next++}`;
    const from = this.frames.length;
    this.ws.send(JSON.stringify({ method, id, params }));
    const reply = await this.until(() => this.frames.slice(from).find((f) => f.id === id), 8000, `the ${method} reply`);
    return { reply, frames: this.frames.slice(from), result: reply.result, error: reply.error };
  }
  notices(from = 0) {
    return this.frames.slice(from).filter((f) => f.method === "message" && f.params?.from?.user_id === "~private");
  }
  close() {
    try {
      this.ws.close(1000, "done");
    } catch {}
  }
}
async function connect() {
  const c = new Conn();
  await c.opened;
  return c;
}
const noticeText = (frames) =>
  frames
    .filter((f) => f.method === "message" && f.params?.from?.user_id === "~private")
    .map((f) => f.params.body?.text ?? "")
    .join("\n");

// HTTP.
await check("GET /healthz is 200", async () => same((await fetch(`${base}/healthz`)).status, 200));
await check("GET / serves the web client", async () => {
  const r = await fetch(`${base}/`);
  const body = await r.text();
  return r.status === 200 && /<html|<!doctype html/i.test(body) ? true : `status ${r.status}`;
});
await check(`AASA lists ${appID}`, async () => {
  const r = await fetch(`${base}/.well-known/apple-app-site-association`);
  const text = await r.text();
  return (r.status === 200 && text.includes(appID)) || `status ${r.status}`;
});
await check("GET /ws?apron_connection_status=1 is available", async () => {
  const r = await fetch(`${wsURL.replace(/^ws/, "http")}?apron_connection_status=1`);
  const body = await r.json();
  return body.available === true || `body ${JSON.stringify(body)}`;
});

// The server frame and welcome notice, with no Origin.
await check("server frame: settings, welcome, ext:media, signup, auth", async () => {
  const c = await connect();
  try {
    const p = (await c.server()).params;
    const problems = [];
    const settings = p.ext?.settings;
    const keys = Object.keys(settings ?? {}).sort().join(",");
    if (keys !== "private_rooms,read_cursors") problems.push(`ext.settings keys ${keys}`);
    if (!p.capabilities?.includes("ext:permissions")) problems.push("no ext:permissions capability");
    const upload = Object.keys(p.ext?.media?.upload ?? {}).sort().join(",");
    if (upload !== "audio/mp4,audio/ogg,audio/webm,image/gif,image/jpeg,image/png,image/webp") problems.push(`ext.media.upload ${upload}`);
    if (p.welcome !== welcome) problems.push("welcome text differs");
    if (!p.ext || !JSON.stringify(p.ext).includes("media")) problems.push("no ext:media");
    if (!p.signup?.includes("token")) problems.push(`signup ${JSON.stringify(p.signup)}`);
    if (!p.auth?.includes("token") || !p.auth?.includes("guest")) problems.push(`auth ${JSON.stringify(p.auth)}`);
    if (p.auth?.includes("webauthn")) problems.push("webauthn offered with no Origin");
    return problems.length === 0 || problems.join("; ");
  } finally {
    c.close();
  }
});

// A guest.
await check("guest: Guest <n> name, requested name ignored", async () => {
  const c = await connect();
  try {
    await c.server();
    const { result, error } = await c.call("auth", { scheme: "guest", name: "Livecheck Name" });
    if (error) return `error ${JSON.stringify(error)}`;
    return /^Guest \d+$/.test(result.you.name) || `name ${JSON.stringify(result.you.name)}`;
  } finally {
    c.close();
  }
});
await check("guest: private welcome notice precedes the auth result", async () => {
  const c = await connect();
  try {
    await c.server();
    const { frames } = await c.call("auth", { scheme: "guest" });
    const all = c.frames;
    const notice = all.findIndex((f) => f.method === "message" && f.params?.from?.user_id === "~private");
    const result = all.findIndex((f) => f.id !== undefined && f.result);
    return (notice >= 0 && notice < result) || `notice at ${notice}, result at ${result}, ${frames.length} frames after send`;
  } finally {
    c.close();
  }
});
await check("guest: posting is denied, history reads", async () => {
  const c = await connect();
  try {
    await c.server();
    await c.call("auth", { scheme: "guest" });
    const post = await c.call("message", { room_id: "general", body: { text: "livecheck must never post" } });
    if (!post.error) return "post was not denied";
    if (!/Guests can only read/.test(post.error.message)) return `message ${JSON.stringify(post.error.message)}`;
    const history = await c.call("history", { room_id: "general" });
    return !history.error || `history ${JSON.stringify(history.error)}`;
  } finally {
    c.close();
  }
});

await check("guest: you says it may not write, keeps its name, and cannot react", async () => {
  const c = await connect();
  try {
    await c.server();
    const { result } = await c.call("auth", { scheme: "guest" });
    const permissions = JSON.stringify(result.you.ext?.permissions);
    if (permissions !== '{"write":false}') return `permissions ${permissions}`;
    const rename = await c.call("me", { name: "Livecheck" });
    if (rename.error?.message !== "Only registered users may change their name") return `me name ${JSON.stringify(rename.error ?? rename.result)}`;
    const history = await c.call("history", { room_id: "general", limit: 1 });
    const id = history.result?.messages?.[0]?.message_id ?? "1";
    const react = await c.call("reactions", { message_id: id, emojis: ["👍"] });
    return react.error?.code === -32001 || `reactions ${JSON.stringify(react.error ?? react.result)}`;
  } finally {
    c.close();
  }
});

// Oversized frame.
await check("17 KiB frame closes with 1009", async () => {
  const c = await connect();
  await c.server();
  c.ws.send(JSON.stringify({ method: "auth", id: "big", params: { scheme: "guest", name: "x".repeat(17 * 1024) } }));
  const end = Date.now() + 8000;
  while (!c.closed && Date.now() < end) await new Promise((r) => setTimeout(r, 50));
  return same(c.closed?.code, 1009);
});

// Admin.
const tokenFile = process.env.APRON_ADMIN_TOKEN_FILE;
if (!tokenFile) {
  console.log("SKIP admin checks (set APRON_ADMIN_TOKEN_FILE)");
} else {
  const adminToken = readFileSync(tokenFile, "utf8").trim();
  const admin = await connect();
  await check("admin: signs in", async () => {
    await admin.server();
    const { result, error } = await admin.call("auth", { scheme: "token", token: adminToken });
    if (error) return `error ${JSON.stringify(error)}`;
    return result.you.user_id === "admin" || `user_id ${result.you.user_id}`;
  });

  const commandRoom = "general";
  const run = (text) => admin.call("command", { room_id: commandRoom, body: { text } });
  const linkToken = (text) => {
    const m = text.match(/https:\/\/link\.apron\.chat\/\S*?token=([^&>\s]+)/);
    return m ? decodeURIComponent(m[1]) : null;
  };

  await check("admin: guest_1 holds the admin role (--role)", async () => {
    const { frames, error } = await run("/role guest_1");
    if (error) return `error ${JSON.stringify(error)}`;
    return /guest_1.*roles? .*`admin`/s.test(noticeText(frames)) || `notice ${noticeText(frames)}`;
  });

  const accountID = `livecheck_${suffix}`;
  await check("admin: /invite-token makes an account that signs in from no Origin", async () => {
    const { frames, error } = await run(`/invite-token ${accountID}`);
    if (error) return `error ${JSON.stringify(error)}`;
    const token = linkToken(noticeText(frames));
    if (!token) return "no link.apron.chat link in the notice";
    const c = await connect();
    try {
      await c.server();
      const signIn = await c.call("auth", { scheme: "token", token });
      if (signIn.error) return `error ${JSON.stringify(signIn.error)}`;
      return signIn.result.you.user_id === accountID || `user_id ${signIn.result.you.user_id}`;
    } finally {
      c.close();
    }
  });

  await check("admin: /invite 1 signs up once, then is denied, /invite 0 revokes", async () => {
    const { frames, error } = await run("/invite 1");
    if (error) return `error ${JSON.stringify(error)}`;
    const token = noticeText(frames).match(/apron_join_[A-Za-z0-9_-]+/)?.[0];
    if (!token) return "no join token in the notice";
    const first = await connect();
    try {
      await first.server();
      const up = await first.call("auth", { scheme: "token", token, name: `livecheck_join_${suffix}` });
      if (up.error) return `sign-up error ${JSON.stringify(up.error)}`;
      if (!up.result.token?.startsWith("apron_invite_")) return "no apron_invite_ token in the result";
    } finally {
      first.close();
    }
    const second = await connect();
    try {
      await second.server();
      const again = await second.call("auth", { scheme: "token", token, name: `livecheck_again_${suffix}` });
      if (!again.error) return "a second use was not denied";
    } finally {
      second.close();
    }
    const revoke = await run("/invite 0");
    return (!revoke.error && /revoked/.test(noticeText(revoke.frames))) || `revoke ${JSON.stringify(revoke.error ?? noticeText(revoke.frames))}`;
  });

  await trackC(admin);

  for (const [command, usage] of [
    ["/role", /Usage: \/role/],
    ["/admin", /Usage: \/admin/],
    ["/toggle", /Usage: \/toggle/],
    ["/kick", /Usage: \/kick <user_id>/],
  ]) {
    await check(`admin: ${command} with no arguments gives its usage`, async () => {
      const { error } = await run(command);
      return (error && usage.test(error.message)) || `reply ${JSON.stringify(error)}`;
    });
  }
  admin.close();
}

// Track C (rooms, messages, permissions), as the admin and the account
// /invite-token made, in a private room the admin makes and leaves.
async function trackC(admin) {
  const room = `livecheck_${suffix}`;
  let roomID, threadID, accountMessage, acct;
  const ok = (r) => !r.error || `error ${JSON.stringify(r.error)}`;
  const code = (r, want) => r.error?.code === want || `reply ${JSON.stringify(r.error ?? r.result)}`;

  await check("C2: the admin's you carries ext.permissions", async () => {
    const { result } = await admin.call("me", {});
    const p = result?.you?.ext?.permissions ?? {};
    return (p.add_members === true && p.move_any === true) || `permissions ${JSON.stringify(p)}`;
  });
  await check("C3: the admin makes a private livecheck_ room", async () => {
    const r = await admin.call("room_set", { title: room, private: true });
    roomID = r.result?.room_id;
    return ok(r);
  });
  if (!roomID) return;
  // A fresh /invite-token account, so its token is at hand.
  const acctID = `livecheck_c_${suffix}`;
  await check("C1: an account may not make a top-level room or edit general", async () => {
    const made = await admin.call("command", { room_id: roomID, body: { text: `/invite-token ${acctID}` } });
    const token = decodeURIComponent(noticeText(made.frames).match(/token=([^&>\s]+)/)?.[1] ?? "");
    if (!token) return "no token";
    acct = await connect();
    await acct.server();
    const signIn = await acct.call("auth", { scheme: "token", token });
    if (signIn.error) return `sign-in ${JSON.stringify(signIn.error)}`;
    const top = await acct.call("room_set", { title: `livecheck_top_${suffix}` });
    if (top.error?.message !== "Only an admin or mod may create a room; others may create threads") return `top-level ${JSON.stringify(top.error ?? top.result)}`;
    const general = await acct.call("room_set", { room_id: "general", title: "livecheck" });
    return general.error?.message === "Only an admin may edit the general room" || `general ${JSON.stringify(general.error ?? general.result)}`;
  });
  await check("C3: only accounts are added, and the admin adds one", async () => {
    const guest = await admin.call("room_join", { room_id: roomID, user_id: "guest_999999" });
    if (guest.error?.code !== -32602) return `guest ${JSON.stringify(guest.error ?? guest.result)}`;
    return ok(await admin.call("room_join", { room_id: roomID, user_id: acctID }));
  });
  await check("C1: threads do not nest", async () => {
    const thread = await admin.call("room_set", { parent_room_id: roomID, title: "livecheck_thread" });
    threadID = thread.result?.room_id;
    if (!threadID) return `thread ${JSON.stringify(thread.error)}`;
    return code(await admin.call("room_set", { parent_room_id: threadID, title: "livecheck_nested" }), -32001);
  });
  await check("C7: a mention over 256 bytes is too_large", async () =>
    code(await acct.call("message", { room_id: roomID, body: { text: "livecheck", mentions: ["x".repeat(300)] } }), -32003));
  await check("C7: a sender's og keeps its text and loses its media", async () => {
    const r = await acct.call("message", {
      room_id: roomID,
      body: { text: "livecheck card", embeds: [{ kind: "link", url: "https://example.com/", og: { title: "Livecheck\ncard", image: { url: "https://example.com/x.png" } } }] },
    });
    if (r.error) return `error ${JSON.stringify(r.error)}`;
    accountMessage = r.result.message_id;
    const sent = r.frames.find((f) => f.method === "message" && f.params?.message_id === accountMessage);
    return same(JSON.stringify(sent?.params?.body?.embeds?.[0]?.og), '{"title":"Livecheck card"}');
  });
  await check("C6: nine emoji are denied, eight are kept", async () => {
    const nine = ["1","2","3","4","5","6","7","8","9"].map((n) => `${n}\uFE0F\u20E3`);
    const denied = await acct.call("reactions", { message_id: accountMessage, emojis: nine });
    if (denied.error?.code !== -32001) return `nine ${JSON.stringify(denied.error ?? denied.result)}`;
    return ok(await acct.call("reactions", { message_id: accountMessage, emojis: nine.slice(0, 8) }));
  });
  await check("C6: a tombstone takes no reactions", async () => {
    const posted = await admin.call("message", { room_id: roomID, body: { text: "livecheck to delete" } });
    const adminMessage = posted.result?.message_id;
    const deleted = await admin.call("message", { message_id: adminMessage, room_id: roomID, deleted: true });
    if (deleted.error) return `delete ${JSON.stringify(deleted.error)}`;
    const r = await acct.call("reactions", { message_id: adminMessage, emojis: ["👍"] });
    return r.error?.message === "cannot react to a deleted message" || `reply ${JSON.stringify(r.error ?? r.result)}`;
  });
  await check("C2: a moderator may not change a message it moves", async () => {
    const back = await admin.call("message", { message_id: accountMessage, room_id: threadID, body: { text: "changed" } });
    return code(back, -32001);
  });
  await check("C5: me ignores an https avatar", async () => {
    const r = await acct.call("me", { avatar: "https://example.com/livecheck.png" });
    return (!r.error && r.result.you.avatar === undefined) || `reply ${JSON.stringify(r.error ?? r.result.you)}`;
  });
  await check("C8: typing is capped at 30 s, and a read cursor reaches no one else", async () => {
    const from = admin.frames.length;
    acct.ws.send(JSON.stringify({ method: "activity", params: { room_id: roomID, typing: 600 } }));
    acct.ws.send(JSON.stringify({ method: "activity", params: { room_id: roomID, read_message_id: accountMessage } }));
    const typing = await admin.until(() => admin.frames.slice(from).find((f) => f.method === "activity" && f.params?.typing !== undefined), 8000, "typing");
    await new Promise((r) => setTimeout(r, 1000));
    const reads = admin.frames.slice(from).filter((f) => f.method === "activity" && f.params?.read_message_id);
    return (typing.params.typing === 30 && reads.length === 0) || `typing ${typing.params.typing}, ${reads.length} read cursors`;
  });
  await check("C10: an upload that is not an image or audio is 415", async () => {
    const r = await acct.call("message", { room_id: roomID, body: { text: "livecheck upload", embeds: [{ kind: "upload", title: "livecheck.txt" }] } });
    const url = r.result?.embeds?.[0]?.write_url;
    if (!url) return `no write_url ${JSON.stringify(r.error ?? r.result)}`;
    const put = await fetch(url, { method: "PUT", headers: { "Content-Type": "text/plain" }, body: "livecheck plain text" });
    return same(put.status, 415);
  });
  await check("C3: /kick removes the account with a private notice", async () => {
    const r = await admin.call("command", { room_id: roomID, body: { text: `/kick ${acctID}` } });
    if (r.error) return `error ${JSON.stringify(r.error)}`;
    return same(noticeText(r.frames), `Removed \`${acctID}\` from this room.`);
  });
  acct?.close();
  await check("C9: the emptied thread and private room are removed", async () => {
    for (const id of [threadID, roomID]) {
      const left = await admin.call("room_leave", { room_id: id });
      if (left.error) return `leave ${JSON.stringify(left.error)}`;
    }
    return code(await admin.call("room_join", { room_id: roomID }), -32602);
  });
}

// Last, because it takes 30 s.
if (slow) {
  await check("unauthenticated connection closes after 30 s", async () => {
    const c = await connect();
    await c.server();
    const start = Date.now();
    const end = start + 40000;
    while (!c.closed && Date.now() < end) await new Promise((r) => setTimeout(r, 250));
    const seconds = (Date.now() - start) / 1000;
    if (!c.closed) return "still open after 40 s";
    return (c.closed.code === 1008 && seconds >= 28 && seconds <= 36) || `code ${c.closed.code} after ${seconds.toFixed(1)} s`;
  });
}

console.log(failed === 0 ? "ALL PASS" : `${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
