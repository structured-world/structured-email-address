import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { contract } from "../../shared/test/contract.js";
import * as ts from "./index.js";

// The trie shipped in the structured-public-domains package, served without a
// network so the suite runs offline.
const require = createRequire(import.meta.url);
const psl = readFileSync(require.resolve("@structured-world/structured-public-domains/psl.bin"));

contract("ts", {
  ...ts,
  init: () => ts.init({ psl: { fetch: async () => new Response(psl), cache: false } }),
});
