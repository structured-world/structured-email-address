// JS twin of bindings/wasm/examples/parity.rs: answer each case from stdin with
// one npm backend and print it as JSON with sorted keys. Its output must be
// byte-identical to the Rust harness; see the `npm` CI job.
//
// The TypeScript backend loads the `psl.bin` its npm dependency ships, the file
// consumers download, read from disk instead of the CDN. The WASM build refuses
// to embed a crate trie that differs from it, so this compares like with like.
// Run: node scripts/parity.mjs <ts|wasm> < cases.jsonl
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // npm/scripts
const which = process.argv[2];
if (which !== "ts" && which !== "wasm") throw new Error("usage: parity.mjs <ts|wasm>");

const backend = await import(join(here, "..", which, "dist", "index.js"));
if (which === "ts") {
  const require = createRequire(join(here, "..", "ts", "package.json"));
  const tiny = require.resolve("@structured-world/structured-public-domains/tiny");
  const bytes = readFileSync(join(dirname(tiny), "psl.bin"));
  await backend.init({ psl: { fetch: async () => new Response(bytes), cache: false } });
} else {
  await backend.init();
}

/** JSON with object keys sorted at every depth, as serde_json's `Value` prints. */
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((k) => [k, sorted(value[k])]),
  );
}

function answer(c) {
  switch (c.op) {
    case "smtp":
      return backend.isSmtpMailbox(c.input);
    case "skeleton":
      return backend.confusableSkeleton(c.input);
    case "parse": {
      const [outcome] = backend.parseBatch([c.input], c.config);
      return outcome.ok
        ? { ok: true, value: outcome.value }
        : { ok: false, error: { kind: outcome.error.kind, position: outcome.error.position } };
    }
    default:
      throw new Error(`unknown op ${c.op}`);
  }
}

/** Write a chunk, waiting for the pipe to drain rather than buffering the run. */
async function write(chunk) {
  if (!process.stdout.write(chunk)) await new Promise((resolve) => process.stdout.once("drain", resolve));
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
let batch = [];
for await (const line of rl) {
  if (line === "") continue;
  batch.push(JSON.stringify(sorted(answer(JSON.parse(line)))) + "\n");
  if (batch.length === 10_000) {
    await write(batch.join(""));
    batch = [];
  }
}
if (batch.length > 0) await write(batch.join(""));
