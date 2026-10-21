import { describe, expect, it, vi } from "vitest";

import { contract } from "../../shared/test/contract.js";
import initModule from "../generated/bindgen/structured_email_address_wasm.js";
import * as wasm from "./index.js";

contract("wasm", { ...wasm, init: () => wasm.init() });

describe("wasm: init", () => {
  // A call made while instantiation is under way joins it: its options are
  // documented as ignored, so they must not even be read, and the embedded
  // module must not be decoded a second time for nothing.
  it("joins a pending init without reading the later call's options", async () => {
    vi.resetModules();
    const fresh = await import("./index.js");
    const first = fresh.init();
    const options = {
      get module(): never {
        throw new Error("options of a joining call were read");
      },
    };
    const second = fresh.init(options);
    await Promise.all([first, second]);
    expect(fresh.isInitialized()).toBe(true);
  });
});

describe("wasm: memory", () => {
  // A one-shot parse builds a configuration inside the module. Left to
  // FinalizationRegistry, which cannot run during a synchronous loop, every
  // call's configuration stayed in linear memory until the loop ended.
  it("frees the configuration of each one-shot parse", async () => {
    await wasm.init();
    // Instantiated already, so this hands back the live instance.
    const { memory } = await initModule({ module_or_path: new Uint8Array() });
    const providers = Array.from({ length: 100 }, (_, i) => ({ domains: [`mail${i}.example.com`] }));
    const before = memory.buffer.byteLength;
    for (let i = 0; i < 5_000; i++) {
      wasm.parse("user@example.com", { providers });
      wasm.parseBatch(["user@example.com"], { providers });
    }
    expect(memory.buffer.byteLength - before).toBeLessThan(4 * 1024 * 1024);
  });
});
