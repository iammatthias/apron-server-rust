// Checks a session.mjs or email.mjs transcript from the Rust aprond: usage
// `node check.mjs transcript.txt`. On each connection (email.mjs labels its
// lines A, B and C), every request got exactly one reply, none an
// internal_error, and the server frame lists the extensions
// apron-server-cloudflare's does; a recorded close is the client's 1000.
import { readFileSync } from "node:fs";

const path = process.argv[2];
if (!path) {
  console.error("usage: node check.mjs transcript.txt");
  process.exit(2);
}
const lines = readFileSync(path, "utf8").trim().split("\n").map((line) => {
  const [, label = "", dir, json] = line.match(/^(?:([A-Z]) )?([<>xh]) (.*)$/);
  return { label, dir, frame: JSON.parse(json) };
});
const problems = [];
for (const label of new Set(lines.map((l) => l.label))) {
  const own = lines.filter((l) => l.label === label);
  const sent = own.filter((l) => l.dir === ">" && l.frame.id !== undefined).map((l) => l.frame.id);
  const replies = own.filter((l) => l.dir === "<" && l.frame.id !== undefined);
  for (const id of sent) {
    const n = replies.filter((r) => r.frame.id === id).length;
    if (n !== 1) problems.push(`${label} request ${id} got ${n} replies`);
  }
  for (const r of replies) {
    if (r.frame.error?.code === -32603) problems.push(`${label} request ${r.frame.id}: internal_error ${r.frame.error.message}`);
  }
  const server = own.find((l) => l.dir === "<" && l.frame.method === "server")?.frame.params;
  for (const capability of ["ext:settings", "ext:media", "ext:permissions", "ext:limits"]) {
    if (!server?.capabilities?.includes(capability)) problems.push(`${label} server frame lacks ${capability}`);
  }
  const close = own.find((l) => l.dir === "x");
  if (close && close.frame.code !== 1000) problems.push(`${label} session ended with ${JSON.stringify(close.frame)}`);
}
const sent = lines.filter((l) => l.dir === ">" && l.frame.id !== undefined);
for (const p of problems) console.log(`FAIL ${p}`);
console.log(problems.length === 0 ? `ok ${sent.length} requests` : `${problems.length} problems`);
process.exit(problems.length === 0 ? 0 : 1);
