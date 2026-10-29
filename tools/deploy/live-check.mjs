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
// /invite sign-up, and one that is renamed and purged. At the end the admin
// purges every livecheck_ account in general, this run's and any an earlier
// run left. The Track C checks post only in a
// private room named livecheck_<random> that the admin makes, and its
// thread; both go when the script empties them. The emoji checks add a
// :livecheck_<random>: custom emoji and remove it again, so every connection
// gets two new server frames. The push checks make one more livecheck_
// account, which registers an fcm.googleapis.com endpoint and unregisters it
// at once; nothing mentions that account, so no push is ever sent.
import { createECDH, randomBytes } from "node:crypto";
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

// The server closes a connection past 60 frames a minute and every
// connection of an address past 120, so the script keeps under both.
const sent = [];
let nextID = 1;
async function pace(own) {
  for (;;) {
    const now = Date.now();
    for (const list of [sent, own]) while (list.length && list[0] <= now - 60000) list.shift();
    if (sent.length < 100 && own.length < 50) break;
    await new Promise((r) => setTimeout(r, Math.min(sent[0] ?? now, own[0] ?? now) + 60001 - now));
  }
  sent.push(Date.now());
  own.push(Date.now());
}

// One WebSocket with every frame it received, in order.
class Conn {
  frames = [];
  closed = null;
  sent = [];
  #waiters = [];
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
    // The server keeps an account's request ids as idempotency keys for a
    // day, so ids are unique across the run's connections and its reruns.
    const id = `lc-${suffix}-${nextID++}`;
    await pace(this.sent);
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
// Opens a connection, waiting out a retry_after the server refuses it with
// (its admission limit, 12 an address a minute), as clients do.
async function connect() {
  for (let attempt = 0; ; attempt++) {
    const c = new Conn();
    await c.opened;
    await c.until(() => c.frames.some((f) => f.method === "server"), 8000, "the server frame");
    await c.until(() => c.frames.length > 1 || c.closed, 8000, "the welcome");
    const refusal = c.frames.find((f) => f.error && f.id === undefined);
    if (!refusal || attempt >= 5) return c;
    c.close();
    await new Promise((r) => setTimeout(r, (refusal.error.data?.retry_after ?? 5) * 1000));
  }
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
    if (!p.capabilities?.includes("ext:limits")) problems.push("no ext:limits capability");
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

await check("server frame: title, description, and ext.media.emoji", async () => {
  const c = await connect();
  try {
    const p = (await c.server()).params;
    const problems = [];
    if (typeof p.title !== "string" || !p.title) problems.push(`title ${JSON.stringify(p.title)}`);
    if (typeof p.description !== "string" || !p.description) problems.push(`description ${JSON.stringify(p.description)}`);
    const emoji = Object.keys(p.ext?.media?.emoji ?? {}).sort().join(",");
    if (emoji !== "image/gif,image/jpeg,image/png,image/webp") problems.push(`ext.media.emoji ${emoji}`);
    const listed = p.capabilities?.includes("ext:emoji");
    if (listed !== (p.ext?.emoji?.catalog_url !== undefined)) problems.push("ext:emoji and ext.emoji.catalog_url disagree");
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

await check("guest: push.wake has no joined, and push_register is denied", async () => {
  const c = await connect();
  try {
    const wake = JSON.stringify((await c.server()).params.push?.wake);
    if (wake !== '["mentions","replies","private","badge"]') return `push.wake ${wake}`;
    await c.call("auth", { scheme: "guest" });
    const r = await c.call("push_register", { kind: "relay", url: "https://fcm.googleapis.com/fcm/send/livecheck" });
    return (r.error?.code === -32001 && r.error.message === "Sign in to receive push notifications") || `reply ${JSON.stringify(r.error ?? r.result)}`;
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

  await check("admin: matthias holds the admin role (--role)", async () => {
    const { frames, error } = await run("/role matthias");
    if (error) return `error ${JSON.stringify(error)}`;
    return /matthias.*roles? .*`admin`/s.test(noticeText(frames)) || `notice ${noticeText(frames)}`;
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

  await check("admin: a server frame listing wake scope joined follows the sign-in", async () => {
    const frame = await admin.until(() => admin.frames.filter((f) => f.method === "server")[1], 8000, "a second server frame");
    return same(JSON.stringify(frame.params.push?.wake), '["mentions","replies","private","joined","badge"]');
  });

  await pushChecks(run, linkToken);
  await renameAndPurge(adminToken, linkToken);

  await trackC(admin);
  admin.close();

  for (const [command, usage] of [
    ["/role", /Usage: \/role/],
    ["/admin", /Usage: \/admin/],
    ["/toggle", /Usage: \/toggle/],
    ["/kick", /Usage: \/kick <user_id>/],
  ]) {
    // A usage error is invalid_params, which the server counts against the
    // connection (3 in a minute close it), so each runs on its own.
    await check(`admin: ${command} with no arguments gives its usage`, async () => {
      const own = await connect();
      try {
        const signIn = await own.call("auth", { scheme: "token", token: adminToken });
        if (signIn.error) return `sign-in ${JSON.stringify(signIn.error)}`;
        const { error } = await own.call("command", { room_id: commandRoom, body: { text: command } });
        return (error && usage.test(error.message)) || `reply ${JSON.stringify(error)}`;
      } finally {
        own.close();
      }
    });
  }

  await cleanUp(adminToken);
}

// /rename and /purge on a livecheck_ account of their own: a rename moves
// its connection and its token to the new user_id, and a purge closes the
// connection and revokes the token. The admin runs them on a connection of
// its own, since the retired user_id's invalid_params counts against it.
async function renameAndPurge(adminToken, linkToken) {
  const admin = await connect();
  const own = await admin.call("auth", { scheme: "token", token: adminToken });
  if (own.error) {
    report("rename: the admin signs in", false, JSON.stringify(own.error));
    admin.close();
    return;
  }
  const run = (text) => admin.call("command", { room_id: "general", body: { text } });
  const from = `livecheck_rn_${suffix}`;
  const to = `livecheck_renamed_${suffix}`;
  const { frames, error } = await run(`/invite-token ${from}`);
  const token = !error && linkToken(noticeText(frames));
  if (!token) {
    report("rename: a livecheck_ account to rename", false, `error ${JSON.stringify(error)}`);
    admin.close();
    return;
  }
  const c = await connect();
  const signIn = async () => {
    const other = await connect();
    try {
      await other.server();
      return await other.call("auth", { scheme: "token", token });
    } finally {
      other.close();
    }
  };
  try {
    await c.server();
    const first = await c.call("auth", { scheme: "token", token });
    if (first.error) {
      report("rename: the account signs in", false, JSON.stringify(first.error));
      return;
    }
    await check("rename: /rename moves the account, its connection and its token", async () => {
      const seen = c.frames.length;
      const r = await run(`/rename @${from} @${to}`);
      if (r.error) return `error ${JSON.stringify(r.error)}`;
      if (noticeText(r.frames) !== `Renamed \`${from}\` to \`${to}\`.`) return `notice ${noticeText(r.frames)}`;
      const you = await c.until(() => c.frames.slice(seen).find((f) => f.method === "user" && f.params.you), 8000, "user you");
      if (you.params.you.user_id !== to) return `you ${JSON.stringify(you.params.you)}`;
      const again = await signIn();
      return again.result?.you?.user_id === to || `token signs in as ${JSON.stringify(again.result?.you ?? again.error)}`;
    });
    await check("rename: the old user_id is retired", async () => {
      const r = await run(`/invite-token ${from}`);
      return r.error?.message === `The user_id ${from} is taken` || `reply ${JSON.stringify(r.error ?? noticeText(r.frames))}`;
    });
    await check("purge: /purge closes the connection and revokes the token", async () => {
      const r = await run(`/purge ${to}`);
      if (r.error) return `error ${JSON.stringify(r.error)}`;
      if (noticeText(r.frames) !== `Purged \`${to}\`: 0 messages, 0 reaction sets, 0 uploads.`) return `notice ${noticeText(r.frames)}`;
      const closing = await c.until(() => c.frames.find((f) => f.error && f.id === undefined) ?? (c.closed && { closed: c.closed }), 8000, "the close");
      if (closing.error?.message !== "Removed by an admin") return `closed with ${JSON.stringify(closing)}`;
      const again = await signIn();
      return again.error?.message === "This invite token is not valid; ask an admin for a new one" || `reply ${JSON.stringify(again.error ?? again.result)}`;
    });
  } finally {
    c.close();
    admin.close();
  }
}

// Purges every livecheck_ account the admin sees in general, and then any
// livecheck_ bot whose owner went first, as a separate connection, so a
// check that failed above does not stop it.
async function cleanUp(adminToken) {
  const admin = await connect();
  try {
    const signIn = await admin.call("auth", { scheme: "token", token: adminToken });
    if (signIn.error) {
      report("cleanup: the admin signs in", false, JSON.stringify(signIn.error));
      return;
    }
    const left = async () => {
      const { result, error } = await admin.call("room_list", { room_id: "general", members: true });
      if (error) throw new Error(`room_list ${JSON.stringify(error)}`);
      const members = result.joined?.find((r) => r.room_id === "general")?.members ?? [];
      return members.map((m) => m.user_id).filter((id) => /^(bot_)?livecheck_/.test(id));
    };
    let purged = 0;
    await check("cleanup: every livecheck_ account is purged", async () => {
      for (const id of (await left()).filter((id) => !id.startsWith("bot_"))) {
        const r = await admin.call("command", { room_id: "general", body: { text: `/purge ${id}` } });
        if (r.error) return `/purge ${id}: ${JSON.stringify(r.error)}`;
        purged++;
      }
      for (const id of await left()) {
        const r = await admin.call("command", { room_id: "general", body: { text: `/purge ${id}` } });
        if (r.error) return `/purge ${id}: ${JSON.stringify(r.error)}`;
        purged++;
      }
      const remaining = await left();
      return remaining.length === 0 || `still there: ${remaining.join(", ")}`;
    });
    console.log(`     purged ${purged} livecheck_ account(s)`);
  } finally {
    admin.close();
  }
}

// Push (Track D) with a new livecheck_ account: a host outside --push.hosts
// is refused, and an endpoint on fcm.googleapis.com registers and is
// unregistered at once, so no push goes to it.
async function pushChecks(run, linkToken) {
  const accountID = `livecheck_push_${suffix}`;
  const { frames, error } = await run(`/invite-token ${accountID}`);
  const token = !error && linkToken(noticeText(frames));
  if (!token) {
    report("push: a livecheck_ account for the push checks", false, `error ${JSON.stringify(error)}`);
    return;
  }
  const c = await connect();
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const keys = { p256dh: ecdh.getPublicKey().toString("base64url"), auth: randomBytes(16).toString("base64url") };
  const endpoint = `https://fcm.googleapis.com/fcm/send/livecheck-${suffix}`;
  try {
    await c.server();
    const signIn = await c.call("auth", { scheme: "token", token });
    if (signIn.error) {
      report("push: the account signs in", false, JSON.stringify(signIn.error));
      return;
    }
    await check("push: an account's sign-in sends no new server frame", async () => {
      await new Promise((r) => setTimeout(r, 500));
      return same(c.frames.filter((f) => f.method === "server").length, 1);
    });
    await check("push: a host outside --push.hosts is refused", async () => {
      const r = await c.call("push_register", { kind: "webpush", url: "https://push.example.net/livecheck", keys });
      return (r.error?.code === -32602 && r.error.message === "push service not allowed here") || `reply ${JSON.stringify(r.error ?? r.result)}`;
    });
    await check("push: an fcm.googleapis.com endpoint registers, then unregisters", async () => {
      const r = await c.call("push_register", { kind: "webpush", url: endpoint, keys, wake: ["mentions"] });
      if (r.error) return `register ${JSON.stringify(r.error)}`;
      const off = await c.call("push_unregister", { url: endpoint });
      return !off.error || `unregister ${JSON.stringify(off.error)}`;
    });
  } finally {
    await c.call("push_unregister", { url: endpoint }).catch(() => {});
    c.close();
  }
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
  await customEmoji(admin, acct, roomID, accountMessage);
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
    const own = acct.frames.length;
    const typing = await admin.until(() => admin.frames.slice(from).find((f) => f.method === "activity" && f.params?.typing !== undefined), 8000, "typing");
    await new Promise((r) => setTimeout(r, 1000));
    const reads = admin.frames.slice(from).filter((f) => f.method === "activity" && f.params?.read_message_id);
    const echoed = acct.frames.slice(own).filter((f) => f.method === "activity" && f.params?.typing !== undefined);
    return (typing.params.typing === 30 && reads.length === 0 && echoed.length === 0) || `typing ${typing.params.typing}, ${reads.length} read cursors, ${echoed.length} typing echoes`;
  });
  await check("C10: an upload that is not an image or audio is 415", async () => {
    const r = await acct.call("message", { room_id: roomID, body: { text: "livecheck upload", embeds: [{ kind: "upload", title: "livecheck.txt" }] } });
    const url = r.result?.embeds?.[0]?.write_url;
    if (!url) return `no write_url ${JSON.stringify(r.error ?? r.result)}`;
    const put = await fetch(url, { method: "PUT", headers: { "Content-Type": "text/plain" }, body: "livecheck plain text" });
    return same(put.status, 415);
  });
  await check("E3: a burst of posts hits the write limit with retry_after, then recovers", async () => {
    for (let i = 0; i < 40; i++) {
      const r = await acct.call("message", { room_id: roomID, body: { text: `livecheck burst ${i}` } });
      if (!r.error) continue;
      const { code, message, data } = r.error;
      if (code !== -32002 || data?.ext?.limits !== "write" || !(data.retry_after >= 1)) return `post ${i}: ${JSON.stringify(r.error)}`;
      if (message !== "Posting limit reached") return `message ${message}`;
      await new Promise((resolve) => setTimeout(resolve, data.retry_after * 1000 + 250));
      return ok(await acct.call("message", { room_id: roomID, body: { text: "livecheck after the wait" } }));
    }
    return "40 posts were all accepted";
  });
  await check("E8: history pages hold 20 records by default and at most 50", async () => {
    const count = (p) => ["rooms", "messages", "reactions", "memberships"].reduce((n, k) => n + (p?.[k]?.length ?? 0), 0);
    const first = await admin.call("history", { room_id: roomID });
    if (first.error) return `default ${JSON.stringify(first.error)}`;
    if (count(first.result) !== 20 || first.result.more !== true) return `default page ${count(first.result)}, more ${first.result.more}`;
    const most = await admin.call("history", { room_id: roomID, limit: 1000 });
    if (most.error) return `limit 1000 ${JSON.stringify(most.error)}`;
    const n = count(most.result);
    return (n > 20 && (n === 50 || most.result.more === false) && n <= 50) || `limit 1000 page ${n}, more ${most.result.more}`;
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

// ext:emoji: the admin adds a livecheck_ emoji, the account reacts with it in
// the private livecheck room, and the admin removes it.
async function customEmoji(admin, acct, roomID, messageID) {
  const key = `:livecheck_${suffix}:`;
  const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
  const catalogWith = async (from, present) => {
    const frame = await admin.until(() => admin.frames.slice(from).find((f) => {
      if (f.method !== "server") return false;
      return present ? f.params.ext?.emoji?.catalog_url !== undefined : true;
    }), 8000, "a new server frame");
    return frame.params;
  };
  let added = false;
  await check("emoji: /emoji add publishes a catalog in a new server frame", async () => {
    const started = await admin.call("command", { room_id: roomID, body: { text: `/emoji add ${key}`, embeds: [{ kind: "upload" }] } });
    const url = started.result?.embeds?.[0]?.write_url;
    if (!url) return `no write_url ${JSON.stringify(started.error ?? started.result)}`;
    const from = admin.frames.length;
    const put = await fetch(url, { method: "PUT", headers: { "Content-Type": "image/png" }, body: png });
    if (put.status !== 201) return `PUT ${put.status}`;
    added = true;
    const p = await catalogWith(from, true);
    if (!p.capabilities?.includes("ext:emoji")) return "no ext:emoji capability";
    const catalogURL = p.ext.emoji.catalog_url;
    if (!catalogURL.startsWith(`${base}/emoji/`)) return `catalog_url ${catalogURL}`;
    const r = await fetch(catalogURL);
    if (r.status !== 200) return `catalog ${r.status}`;
    if (!/immutable/.test(r.headers.get("cache-control") ?? "")) return `catalog cache ${r.headers.get("cache-control")}`;
    const catalog = JSON.parse(await r.text());
    const entry = catalog[key];
    if (!entry?.url) return `catalog ${JSON.stringify(catalog)}`;
    const image = await fetch(entry.url);
    if (image.status !== 200) return `image ${image.status}`;
    return /immutable/.test(image.headers.get("cache-control") ?? "") || `image cache ${image.headers.get("cache-control")}`;
  });
  await check("emoji: the account reacts with the key in the private room", async () => {
    const r = await acct.call("reactions", { message_id: messageID, emojis: [key, "\u2764"] });
    if (r.error) return `error ${JSON.stringify(r.error)}`;
    const sent = r.frames.find((f) => f.method === "reactions" && f.params?.message_id === messageID);
    return same(JSON.stringify(sent?.params?.reactions?.[0]?.emojis), JSON.stringify([key, "\u2764\uFE0F"]));
  });
  if (!added) return;
  await check("emoji: /emoji remove takes the key out of the catalog", async () => {
    const from = admin.frames.length;
    const r = await admin.call("command", { room_id: roomID, body: { text: `/emoji remove ${key}` } });
    if (r.error) return `error ${JSON.stringify(r.error)}`;
    if (noticeText(r.frames) !== `Removed the custom emoji \`${key}\`.`) return `notice ${noticeText(r.frames)}`;
    const p = await catalogWith(from, false);
    const url = p.ext?.emoji?.catalog_url;
    if (!url) return true;
    const catalog = JSON.parse(await (await fetch(url)).text());
    return !(key in catalog) || "the key is still in the catalog";
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
