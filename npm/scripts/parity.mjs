// JS twin of bindings/wasm/examples/parity.rs: answer each case from stdin with
// one npm backend and print it as JSON with sorted keys. Its output must be
// byte-identical to the Rust harness; see the `npm` CI job.
//
// The TypeScript backend loads the Public Suffix List trie from the crate the
// Rust harness linked, so both read the same list.
// Run: node scripts/parity.mjs <ts|wasm> < cases.jsonl
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // npm/scripts
const which = process.argv[2];
if (which !== "ts" && which !== "wasm") throw new Error("usage: parity.mjs <ts|wasm>");

const backend = await import(join(here, "..", which, "dist", "index.js"));
if (which === "ts") {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--format-version", "1", "--locked"], {
      cwd: join(here, "..", ".."),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    }),
  );
  const psl = metadata.packages.find((p) => p.name === "structured-public-domains");
  const bytes = readFileSync(join(dirname(psl.manifest_path), "src", "psl.bin"));
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
