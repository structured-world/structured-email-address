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
    expect(api.parse("a@Example.co.uk", { domainCheck: "psl" }).domain).toBe("example.co.uk");
    expect(await api.init({ backend: "wasm" })).toBe("wasm");
    expect(api.backend()).toBe("wasm");
    expect(api.parse("a@Example.co.uk", { domainCheck: "psl" }).domain).toBe("example.co.uk");
  });

  // A failed init must not leave the previous backend answering: the caller saw
  // the rejection, and later calls quietly using another backend would hide it.
  it("leaves no backend active after a failed switch", async () => {
    const api = await fresh();
    await api.init({ backend: "ts", ts });
    await expect(api.init({ backend: "wasm", wasm: { module: new Uint8Array([0, 1, 2, 3]) } })).rejects.toThrow();
    expect(api.backend()).toBeUndefined();
    expect(() => api.parse("a@example.com")).toThrow(/init/);
  });

  it("reports both failures when auto can start neither backend", async () => {
    const api = await fresh();
    const failing = { psl: { fetch: async () => Promise.reject(new Error("offline")), cache: false, force: true } };
    const error = await api.init({ ts: failing, wasm: { module: new Uint8Array([0, 1, 2, 3]) } }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AggregateError);
    expect((error as AggregateError).errors).toHaveLength(2);
    expect(api.backend()).toBeUndefined();
  });

  it("errors from either backend are instances of the exported class", async () => {
    const api = await fresh();
    for (const backend of ["wasm", "ts"] as const) {
      await api.init({ backend, ts });
      expect(() => api.parse("bad")).toThrow(api.EmailAddressError);
    }
  });
});
