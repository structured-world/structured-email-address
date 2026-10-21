// Public API for @structured-world/structured-email-address-wasm: the Rust
// crate itself, compiled to WebAssembly with the Public Suffix List embedded,
// so results are the Rust crate's by construction and nothing is fetched.

import { frontend } from "../../shared/src/api.js";
import type { Engine, RawOutcome, ResolvedConfig } from "../../shared/src/types.js";
import initModule, * as wasm from "../generated/bindgen/structured_email_address_wasm.js";
import { WASM_BASE64 } from "../generated/wasm-data.cjs";

export * from "../../shared/src/public.js";

/** Options for {@link init}. */
export interface InitOptions {
  /**
   * A precompiled module or the module's bytes, for environments that compile
   * WebAssembly elsewhere (a worker, a cache). Defaults to the embedded module.
   */
  readonly module?: WebAssembly.Module | BufferSource;
}

let ready = false;
let pending: Promise<void> | undefined;

function decodeBase64(b64: string): Uint8Array {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(b64, "base64"));
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Instantiate the WebAssembly module. Must be awaited before any other
 * function. Idempotent: concurrent and repeated calls share one instance.
 *
 * @throws if the runtime cannot instantiate WebAssembly (no `WebAssembly`
 *   global, or a Content Security Policy without `wasm-unsafe-eval`).
 */
export function init(options: InitOptions = {}): Promise<void> {
  if (ready) return Promise.resolve();
  pending ??= initModule({ module_or_path: options.module ?? decodeBase64(WASM_BASE64) }).then(
    () => {
      ready = true;
    },
    (err: unknown) => {
      // Let a later call retry, for example with a module passed in.
      pending = undefined;
      throw err;
    },
  );
  return pending;
}

/** Whether {@link init} has completed. */
export function isInitialized(): boolean {
  return ready;
}

const engine: Engine<ResolvedConfig> = {
  // The module builds its configuration from the resolved options on each
  // call; there is nothing to hold on to between calls.
  compile: (config) => config,
  parse: (input, config) => wasm.parse(input, config) as RawOutcome,
  parseBatch: (inputs, config) => wasm.parseBatch([...inputs], config) as RawOutcome[],
  isSmtpMailbox: (input) => wasm.isSmtpMailbox(input),
  confusableSkeleton: (input) => wasm.confusableSkeleton(input),
};

const api = frontend(() => {
  if (!ready) throw new Error("not initialized: call `await init()` first");
  return engine;
});

/** Bind a configuration once for many parses. */
export const createParser = api.createParser;
/** Parse and validate one address. @throws {EmailAddressError} */
export const parse = api.parse;
/** Parse many addresses; one outcome per input, in order. */
export const parseBatch = api.parseBatch;
/** ASCII RFC 5321 `Mailbox` syntax test: no normalization, IDNA or PSL. */
export const isSmtpMailbox = api.isSmtpMailbox;
/** The UTS #39 confusable skeleton; equal skeletons look alike. */
export const confusableSkeleton = api.confusableSkeleton;
