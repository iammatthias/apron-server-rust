// Runs an email sign-in session against an aprond started with
// `--email.enable --email.sender log`, reading the codes from its log, and
// prints every frame: usage `node email.mjs ws://host:port/ws server.log`.
// One connection proposes and signs in with a code, a second resumes with
// the bearer token, and a guest adds an address. Codes and bearer tokens
// differ between runs, so the transcript prints them as <code> and <token>.
// It prints each connection's frames together, in the order that connection
// sent and received them: the order across connections depends on thread
// scheduling, not on the server.
import { readFileSync } from "node:fs";

const [url, logPath] = process.argv.slice(2);
if (!url || !logPath) {
  console.error("usage: node email.mjs ws://host:port/ws server.log");
  process.exit(2);
}

const lines = [];
const secrets = new Map();
const masked = (text) => {
  for (const [secret, name] of secrets) {
    text = text.split(secret).join(name);
  }
  return text;
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Opens a connection that records every frame under its label.
const connect = (label) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const conn = { ws, label, inbox: [], waiters: [] };
    ws.onmessage = (event) => {
      const frame = JSON.parse(event.data);
      lines.push(() => `${label} < ${masked(JSON.stringify(frame))}`);
      conn.inbox.push(frame);
      conn.waiters.splice(0).forEach((wake) => wake());
      if (frame.method === "server") resolve(conn);
    };
    ws.onerror = (e) => reject(new Error(e.message));
  });

// Sends a request and waits for its reply, then for the notifications that
// follow it to settle.
const request = async (conn, method, id, params) => {
  const frame = { method, id, params };
  lines.push(() => `${conn.label} > ${masked(JSON.stringify(frame))}`);
  conn.ws.send(JSON.stringify(frame));
  for (;;) {
    const reply = conn.inbox.find((f) => f.id === id);
    if (reply) {
      await sleep(200);
      return reply;
    }
    await new Promise((wake) => conn.waiters.push(wake));
  }
};

// Waits for the log line carrying the code sent to an address.
const codeFor = async (email) => {
  for (let i = 0; i < 100; i++) {
    const log = readFileSync(logPath, "utf8").split("\n");
    const line = log.findLast((l) => l.includes("email sign-in code") && l.includes(email));
    const match = line?.match(/code=(\d{6})/);
    if (match) return match[1];
    await sleep(50);
  }
  throw new Error(`no code for ${email} in ${logPath}`);
};

const timer = setTimeout(() => {
  console.error("timeout");
  process.exit(1);
}, 15000);

const a = await connect("A");
await request(a, "auth", "propose", { scheme: "email", email: "Ada@Example.com" });
const code = await codeFor("ada@example.com");
secrets.set(code, "<code>");
const signedIn = await request(a, "auth", "approve", { scheme: "email", token: code, name: "Ada" });
const token = signedIn.result.token;
secrets.set(token, "<token>");
await request(a, "room_list", "list", {});

const b = await connect("B");
await request(b, "auth", "resume", { scheme: "token", token });
await request(b, "auth", "wrong", { scheme: "token", token: "nope" });

const c = await connect("C");
await request(c, "auth", "guest", { scheme: "guest", name: "Guest" });
await request(c, "auth", "add", { scheme: "email", email: "bob@example.com" });
const addCode = await codeFor("bob@example.com");
secrets.set(addCode, "<add-code>");
await request(c, "auth", "approve-add", { scheme: "email", token: addCode });
await request(c, "me", "me", {});

for (const conn of [a, b, c]) conn.ws.close(1000, "done");
await sleep(200);
clearTimeout(timer);
for (const label of ["A", "B", "C"]) {
  for (const line of lines) {
    const text = line();
    if (text.startsWith(`${label} `)) console.log(text);
  }
}
