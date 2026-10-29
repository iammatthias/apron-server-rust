// Compares the shape of the `server` frame and a guest's `auth` result
// between the live reference and this server, read-only: one guest
// connection to each, which signs in and closes. Shape means the key paths
// and the members of the enumerations (capabilities, auth schemes, statuses,
// wake scopes), not the values. Prints what only one side has, and exits 1
// when the shapes differ.
//
//   node tools/smoke/frame-diff.mjs [ours-url [ours-origin]]
//
// ours-url defaults to wss://apron.farfield.systems/ws and ours-origin to
// that host's https origin. The reference is wss://server.apron.chat/ from
// https://web.apron.chat, the web client's origin.
const REFERENCE = { url: "wss://server.apron.chat/", origin: "https://web.apron.chat" };
const oursURL = process.argv[2] ?? "wss://apron.farfield.systems/ws";
const ours = { url: oursURL, origin: process.argv[3] ?? new URL(oursURL.replace(/^ws/, "http")).origin };

// Lists whose members are names, compared as members; any other list is
// compared by the shape of its elements.
const ENUMERATIONS = new Set(["server.capabilities", "server.auth", "server.signup", "server.status", "server.push.wake"]);

function shape(value, path, out) {
  if (Array.isArray(value)) {
    if (ENUMERATIONS.has(path)) {
      for (const member of value) out.add(`${path} ∋ ${member}`);
      return out;
    }
    out.add(`${path}[]`);
    for (const element of value) shape(element, `${path}[]`, out);
  } else if (value !== null && typeof value === "object") {
    for (const [key, inner] of Object.entries(value)) {
      out.add(`${path}.${key}`);
      shape(inner, `${path}.${key}`, out);
    }
  }
  return out;
}

function probe({ url, origin }) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers: { Origin: origin } });
    const found = new Set();
    const timer = setTimeout(() => { ws.close(); reject(new Error(`${url}: no answer in 15 s`)); }, 15_000);
    ws.onerror = (event) => { clearTimeout(timer); reject(new Error(`${url}: ${event.message ?? "error"}`)); };
    ws.onmessage = (event) => {
      const frame = JSON.parse(event.data);
      if (frame.method === "server" && !found.has("server")) {
        found.add("server");
        shape(frame.params, "server", found);
        ws.send(JSON.stringify({ method: "auth", id: "auth", params: { scheme: "guest" } }));
      } else if (frame.id === "auth") {
        clearTimeout(timer);
        shape(frame.result ?? { error: frame.error }, "auth", found);
        ws.close(1000);
        found.delete("server");
        resolve(found);
      }
    };
  });
}

const [theirs, mine] = await Promise.all([probe(REFERENCE), probe(ours)]);
const only = (a, b) => [...a].filter((key) => !b.has(key)).sort();
const reference = only(theirs, mine);
const local = only(mine, theirs);
console.log(`reference ${REFERENCE.url} (Origin ${REFERENCE.origin})`);
console.log(`ours      ${ours.url} (Origin ${ours.origin})`);
console.log(`${[...theirs].filter((key) => mine.has(key)).length} paths in both`);
console.log(`\nonly the reference has (${reference.length}):`);
for (const key of reference) console.log(`  ${key}`);
console.log(`\nonly ours has (${local.length}):`);
for (const key of local) console.log(`  ${key}`);
process.exit(reference.length || local.length ? 1 : 0);
