#!/usr/bin/env node
// Reads every public room on the Apron demo server as a guest, with their threads, and prints
// the messages posted since the last run. The demo's rooms are where client and server authors share what
// they are building, so this is the other half of check.sh's review queue.
//
//   node tools/reference/demo-room.mjs [room_id] [--all]
//
// A room_id reads only that room and its threads. Each run appends what it printed to
// tools/reference/.demo-room/<room_id>.md and remembers the last message per room in
// state.json there (git ignores the directory). --all prints the whole history again.
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const server = process.env.APRON_DEMO_URL ?? "wss://server.apron.chat/ws";
const args = process.argv.slice(2);
const all = args.includes("--all");
const roomID = args.find((a) => !a.startsWith("--")) ?? "all";
const dir = join(dirname(fileURLToPath(import.meta.url)), ".demo-room");
const statePath = join(dir, "state.json");
mkdirSync(dir, { recursive: true });
let state = {};
try {
  state = JSON.parse(readFileSync(statePath, "utf8"));
} catch {}

const ws = new WebSocket(server);
const replies = new Map();
let nextID = 0;
ws.onmessage = (event) => {
  const frame = JSON.parse(event.data);
  if (frame.id && replies.has(frame.id)) {
    replies.get(frame.id)(frame);
    replies.delete(frame.id);
  } else if (frame.method === "server") {
    serverFrame(frame);
  }
};
let serverFrame;
const opened = new Promise((resolve, reject) => {
  serverFrame = resolve;
  ws.onerror = () => reject(new Error(`could not connect to ${server}`));
  ws.onclose = (event) => reject(new Error(`closed ${event.code} ${event.reason}`));
});
function call(method, params) {
  const id = `demo-${++nextID}`;
  ws.send(JSON.stringify({ method, id, params }));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no reply to ${method}`)), 15000);
    replies.set(id, (frame) => {
      clearTimeout(timer);
      if (frame.error) reject(new Error(`${method}: ${JSON.stringify(frame.error)}`));
      else resolve(frame.result);
    });
  });
}

// Every message after `after`, or the whole history when there is none, oldest first.
async function messagesSince(room, after) {
  const found = [];
  if (after) {
    for (let cursor = after; ; ) {
      const page = await call("history", { room_id: room, after: cursor, limit: 50 });
      // The demo's `after` includes the record at the cursor.
      found.push(...(page.messages ?? []).filter((m) => Number(m.log_id) > Number(after)));
      if (!page.more || !page.messages?.length) return found;
      cursor = page.last_log_id;
    }
  }
  for (let page = await call("history", { room_id: room, limit: 50 }); ; ) {
    found.unshift(...(page.messages ?? []));
    if (!page.more || !page.messages?.length) return found;
    page = await call("history", { room_id: room, before: page.first_log_id, limit: 50 });
  }
}

function render(message) {
  const when = new Date(Number(message.message_id)).toISOString().slice(0, 16).replace("T", " ");
  const who = message.from?.name ?? message.from?.user_id ?? "?";
  const text = message.body?.text ?? (message.deleted ? "(deleted)" : "");
  const embeds = (message.body?.embeds ?? []).map((e) => e.url).filter(Boolean);
  // An edit or a delete logs the message again under a newer log_id.
  const changed = message.log_id && message.log_id !== message.message_id ? " (changed)" : "";
  return `- ${when} **${who}**${changed}: ${text.trim().replace(/\n/g, "\n  ")}${embeds.length ? `\n  embeds: ${embeds.join(" ")}` : ""}`;
}

const listed = (result) => [...(result.joined ?? []), ...(result.rooms ?? []), ...(result.not_joined ?? [])];

try {
  await opened;
  await call("auth", { scheme: "guest" });
  // A guest joins general and sees every other public room as not joined.
  const top = [...listed(await call("room_list", {})), ...listed(await call("room_list", { filter: "not_joined" }))]
    .filter((r) => !r.parent_room_id && (roomID === "all" || r.room_id === roomID));
  const seen = new Set();
  const rooms = [];
  for (const r of top) {
    if (seen.has(r.room_id)) continue;
    seen.add(r.room_id);
    const title = r.title ?? r.room_id;
    rooms.push({ room_id: r.room_id, label: title });
    for (const t of listed(await call("room_list", { parent_room_id: r.room_id, filter: "not_joined" })))
      rooms.push({ room_id: t.room_id, label: `${title} › ${t.title ?? t.room_id}` });
  }
  let out = "";
  for (const r of rooms) {
    const records = await messagesSince(r.room_id, all ? null : state[r.room_id]);
    if (!records.length) continue;
    state[r.room_id] = records.at(-1).log_id ?? records.at(-1).message_id;
    // History logs each edit, delete and move again; print each message once, as it is now.
    const latest = new Map(records.map((m) => [m.message_id, m]));
    const messages = [...latest.values()].sort((a, b) => Number(a.message_id) - Number(b.message_id));
    out += `\n## ${r.label} (${messages.length} new)\n\n${messages.map(render).join("\n")}\n`;
  }
  const stamp = new Date().toISOString().slice(0, 16).replace("T", " ");
  if (out) {
    process.stdout.write(out);
    appendFileSync(join(dir, `${roomID}.md`), `\n# Read ${stamp} UTC\n${out}`);
  } else {
    console.log(`nothing new in ${rooms.length} rooms and threads`);
  }
  writeFileSync(statePath, JSON.stringify(state, null, 1));
} finally {
  ws.close(1000, "done");
}
