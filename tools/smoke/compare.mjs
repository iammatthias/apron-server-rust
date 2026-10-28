// Compares two session.mjs transcripts, one from the Go aprond and one from
// this one: usage `node compare.mjs go.txt rust.txt`.
//
// log_ids are commit times, so they differ between runs. Masking them hides
// their relationships too: a frame that reported an older record's id where
// the newer one's belonged would still compare equal. Instead each distinct
// 13-digit id is replaced by #N, N being the order of its first appearance in
// the transcript, so two transcripts agree only when every id refers to the
// same record relative to the others. The server frame's agent is masked, as
// the two servers name themselves differently (docs/DEVIATIONS.md), and so
// are the listen address and the random write tokens and file secrets.
import { readFileSync } from "node:fs";

const [goPath, rustPath] = process.argv.slice(2);
if (!goPath || !rustPath) {
  console.error("usage: node compare.mjs go.txt rust.txt");
  process.exit(2);
}

const normalize = (text) => {
  const ids = new Map();
  return text
    .replace(/"agent":"apron-(go|rust)\/9"/g, '"agent":"apron-*/9"')
    .replace(/127\.0\.0\.1:\d+/g, "HOST")
    .replace(/\/write\/[A-Z2-7]{26}/g, "/write/TOKEN")
    .replace(/(\/(files|streams)\/embed_\d+\/)[A-Z2-7]{26}/g, "$1SECRET")
    .replace(/\b1\d{12}\b/g, (id) => {
      if (!ids.has(id)) {
        ids.set(id, `#${ids.size + 1}`);
      }
      return ids.get(id);
    })
    .split("\n")
    .filter((line) => line !== "");
};

const go = normalize(readFileSync(goPath, "utf8"));
const rust = normalize(readFileSync(rustPath, "utf8"));
let differences = 0;
for (let i = 0; i < Math.max(go.length, rust.length); i++) {
  if (go[i] !== rust[i]) {
    differences++;
    console.log(`line ${i + 1}`);
    console.log(`  go:   ${go[i] ?? "<missing>"}`);
    console.log(`  rust: ${rust[i] ?? "<missing>"}`);
  }
}
if (differences === 0) {
  console.log(`identical: ${go.length} lines, ids compared by order of first appearance`);
} else {
  console.log(`${differences} differing line(s)`);
  process.exit(1);
}
