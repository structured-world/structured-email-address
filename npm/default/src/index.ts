// Public API for @structured-world/structured-email-address: one API over
// either backend. Both are optional dependencies; `init()` loads only the one
// it selects, through a dynamic import a bundler splits into its own chunk.

import type { Config, EmailAddress } from "../../shared/src/types.js";
import type { ParseOutcome, Parser } from "../../shared/src/api.js";
import type * as TsBackend from "@structured-world/structured-email-address-ts";
import type * as WasmBackend from "@structured-world/structured-email-address-wasm";

export * from "../../shared/src/public.js";

/** Which implementation answers. */
export type Backend = "wasm" | "ts";

/** Options for {@link init}. */
export interface InitOptions {
  /**
   * `"wasm"` or `"ts"` to require one backend; `"auto"` (the default) to use
   * WebAssembly where it can be instantiated and TypeScript otherwise.
   */
  readonly backend?: Backend | "auto";
  /** Passed to the WebAssembly backend's `init`. */
  readonly wasm?: WasmBackend.InitOptions;
  /** Passed to the TypeScript backend's `init`. */
  readonly ts?: TsBackend.InitOptions;
}

type Module = typeof TsBackend | typeof WasmBackend;

let active: { readonly name: Backend; readonly module: Module } | undefined;

async function start(name: Backend, options: InitOptions): Promise<Backend> {
  if (name === "wasm") {
    const module = await import("@structured-world/structured-email-address-wasm");
    await module.init(options.wasm);
    active = { name, module };
  } else {
    const module = await import("@structured-world/structured-email-address-ts");
    await module.init(options.ts);
    active = { name, module };
  }
  return name;
}

/**
 * Load a backend. Must be awaited before any other function; a later call
 * switches to the backend it names.
 *
 * `"auto"` prefers WebAssembly, which is the Rust crate itself and needs no
 * network. It falls back to TypeScript when WebAssembly is missing or refused,
 * as under a Content Security Policy without `wasm-unsafe-eval`, and when the
 * WebAssembly package is not installed.
 *
 * @returns the backend now in use.
 * @throws if the requested backend, or under `"auto"` both, cannot start.
 */
export async function init(options: InitOptions = {}): Promise<Backend> {
  const choice = options.backend ?? "auto";
  if (choice !== "auto") return start(choice, options);
  if (typeof WebAssembly === "object") {
    try {
      return await start("wasm", options);
    } catch {
      // Fall through to the backend that needs no WebAssembly.
    }
  }
  return start("ts", options);
}

/** The backend in use, or `undefined` before {@link init}. */
export function backend(): Backend | undefined {
  return active?.name;
}

function current(): Module {
  if (active === undefined) throw new Error("not initialized: call `await init()` first");
  return active.module;
}

/** Bind a configuration once for many parses, on the backend in use now. */
export function createParser(config?: Config): Parser {
  return current().createParser(config);
}

/** Parse and validate one address. @throws {EmailAddressError} */
export function parse(input: string, config?: Config): EmailAddress {
  return current().parse(input, config);
}

/** Parse many addresses; one outcome per input, in order. */
export function parseBatch(inputs: readonly string[], config?: Config): ParseOutcome[] {
  return current().parseBatch(inputs, config);
}

/** ASCII RFC 5321 `Mailbox` syntax test: no normalization, IDNA or PSL. */
export function isSmtpMailbox(input: string): boolean {
  return current().isSmtpMailbox(input);
}

/** The UTS #39 confusable skeleton; equal skeletons look alike. */
export function confusableSkeleton(input: string): string {
  return current().confusableSkeleton(input);
}
