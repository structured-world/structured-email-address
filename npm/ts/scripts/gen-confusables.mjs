// Generate generated/confusables-data.ts from the Rust crate's unicode-security
// tables, so the TypeScript skeleton reads the same data as the Rust one.
// Runs on every build; the output is never committed.
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // npm/ts/scripts
const repo = join(here, "..", "..", "..");
const outDir = join(here, "..", "generated");

const table = execFileSync(
  "cargo",
  ["run", "--quiet", "--locked", "-p", "structured-email-address-wasm", "--example", "confusables"],
  { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], maxBuffer: 16 * 1024 * 1024 },
);

mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "confusables-data.ts"), table);
console.log(`confusables-data.ts: ${table.length} chars`);
