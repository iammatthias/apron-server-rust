// Runs one guest session against an aprond and prints every frame, so the
// Go and Rust servers can be compared: usage `node session.mjs ws://host:port/ws`.
// Besides the WebSocket frames it prints the one HTTP exchange, the upload's
// PUT, as `h`. Compare two transcripts with compare.mjs.
const url = process.argv[2] ?? "ws://127.0.0.1:8080/ws";
const ws = new WebSocket(url);
const frames = [];
let step = 0;
let writeURL;
const script = [
  { method: "auth", id: "a1", params: { scheme: "guest", name: "Smoke" } },
  { method: "message", id: "m1", params: { room_id: "general", body: { text: "hello from smoke" }, ext: { "__proto__": { x: 1 }, big: 12345678901234567890 } } },
  { method: "status", id: "s1", params: { idle: false, mute: 5 } },
  { method: "status", id: "s2", params: { room_id: "general", mute: true } },
  { method: "status", id: "s3", params: { room_id: "general", mute: false } },
  { method: "command", id: "c1", params: { body: { text: "/help" } } },
  { method: "command", id: "c2", params: { body: { text: "/nope" } } },
  { method: "message", id: "m2", params: { room_id: "general", body: { text: "a file", embeds: [{ kind: "upload", title: "notes.txt" }, { kind: "link", url: "https://example.com" }] } } },
  // The upload's PUT: the server republishes the message before answering,
  // so the republished snapshot precedes the next request's reply.
  async () => {
    const response = await fetch(writeURL, { method: "PUT", body: "hello from the upload", headers: { "Content-Type": "text/plain" } });
    frames.push({ dir: "h", frame: { status: response.status, body: await response.text() } });
    next();
  },
  { method: "history", id: "h1", params: { room_id: "general" } },
  { method: "room_list", id: "r1", params: { members: true } },
  { method: "ping" },
];
const next = () => {
  if (step >= script.length) {
    ws.close(1000, "done");
    return;
  }
  const frame = script[step++];
  if (typeof frame === "function") {
    frame();
    return;
  }
  frames.push({ dir: ">", frame });
  ws.send(JSON.stringify(frame));
};
ws.onopen = () => {};
ws.onmessage = (event) => {
  frames.push({ dir: "<", frame: JSON.parse(event.data) });
  const frame = frames.at(-1).frame;
  if (frame.id === "m2") {
    writeURL = frame.result.embeds[0].write_url;
  }
  // The server frame starts the script; each reply or pong advances it.
  if (frame.method === "server" || frame.id !== undefined || frame.method === "pong") {
    next();
  }
};
ws.onclose = (event) => {
  clearTimeout(timer);
  frames.push({ dir: "x", code: event.code, reason: event.reason });
  for (const f of frames) {
    console.log(f.dir, JSON.stringify(f.frame ?? { code: f.code, reason: f.reason }));
  }
};
ws.onerror = (e) => {
  console.error("error", e.message);
  process.exit(1);
};
const timer = setTimeout(() => {
  console.error("timeout");
  process.exit(1);
}, 5000);
