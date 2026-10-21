// Backend selection. Each test re-imports the module, so selection state does
// not leak between them.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { afterEach, describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const psl = readFileSync(require.resolve("@structured-world/structured-public-domains/psl.bin"));
const ts = { psl: { fetch: async () => new Response(psl), cache: false } };

async function fresh() {
  vi.resetModules();
  return import("./index.js");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("init", () => {
  it("refuses to parse before a backend is chosen", async () => {
    const api = await fresh();
    expect(api.backend()).toBeUndefined();
    expect(() => api.parse("a@example.com")).toThrow(/init/);
  });

  it("prefers WebAssembly under auto", async () => {
    const api = await fresh();
    expect(await api.init({ ts })).toBe("wasm");
    expect(api.backend()).toBe("wasm");
    expect(api.parse("a@Example.com").domain).toBe("example.com");
  });

  it("falls back to TypeScript where WebAssembly is unavailable", async () => {
    vi.stubGlobal("WebAssembly", undefined);
    const api = await fresh();
    expect(await api.init({ ts })).toBe("ts");
    expect(api.parse("a@Example.com").domain).toBe("example.com");
  });

  it("falls back to TypeScript when WebAssembly refuses to instantiate", async () => {
    // A CSP without wasm-unsafe-eval rejects instantiation; a corrupt module
    // fails the same call the same way.
    const api = await fresh();
    expect(await api.init({ ts, wasm: { module: new Uint8Array([0, 1, 2, 3]) } })).toBe("ts");
  });

  it("uses the backend asked for, and switches on a later call", async () => {
    const api = await fresh();
    expect(await api.init({ backend: "ts", ts })).toBe("ts");
    expect(await api.init({ backend: "wasm" })).toBe("wasm");
    expect(api.backend()).toBe("wasm");
  });

  it("errors from either backend are instances of the exported class", async () => {
    const api = await fresh();
    for (const backend of ["wasm", "ts"] as const) {
      await api.init({ backend, ts });
      expect(() => api.parse("bad")).toThrow(api.EmailAddressError);
    }
  });
});
