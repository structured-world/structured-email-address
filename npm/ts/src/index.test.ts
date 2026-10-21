import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { DEFAULT_PSL_URL } from "@structured-world/structured-public-domains/tiny";
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
  // structured-public-domains publishes a data release almost daily, and its
  // loader's default URL tracks the newest one. A URL pinned to the build-time
  // release would freeze the list until this package is released again.
  it("fetches from the loader's default URL, which tracks the newest release", async () => {
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
    expect(urls).toEqual([DEFAULT_PSL_URL]);
  });
});
