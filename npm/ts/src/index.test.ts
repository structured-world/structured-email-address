import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { contract } from "../../shared/test/contract.js";
import * as ts from "./index.js";

// The trie shipped in the structured-public-domains package, served without a
// network so the suite runs offline.
const require = createRequire(import.meta.url);
const pslPath = require.resolve("@structured-world/structured-public-domains/psl.bin");
const psl = readFileSync(pslPath);

contract("ts", {
  ...ts,
  init: () => ts.init({ psl: { fetch: async () => new Response(psl), cache: false } }),
});

describe("ts: default trie source", () => {
  // The WebAssembly backend embeds the trie of one structured-public-domains
  // release. The loader's own default URL follows the newest 0.0.x release on
  // the CDN, so after the next PSL update the two backends would answer from
  // different lists. The default must name the release this build was checked
  // against.
  it("fetches the psl.bin of the release it was built against", async () => {
    const { version } = JSON.parse(readFileSync(join(dirname(pslPath), "..", "package.json"), "utf8")) as {
      version: string;
    };
    const urls: string[] = [];
    // `force`: the contract suite above has already loaded a trie.
    await ts.init({
      psl: {
        cache: false,
        force: true,
        fetch: async (url) => {
          urls.push(String(url));
          return new Response(psl);
        },
      },
    });
    expect(urls).toEqual([
      `https://cdn.jsdelivr.net/npm/@structured-world/structured-public-domains@${version}/dist/psl.bin`,
    ]);
  });
});
