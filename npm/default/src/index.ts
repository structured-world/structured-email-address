// Public API for @structured-world/structured-email-address: one API over
// either backend. Both are optional dependencies; `init()` loads only the one
// it selects, through a dynamic import a bundler splits into its own chunk.

import type { Config, EmailAddress, TsInitOptions, WasmInitOptions } from "../../shared/src/types.js";
import type { Frontend, ParseOutcome, Parser } from "../../shared/src/api.js";

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
  readonly wasm?: WasmInitOptions;
  /** Passed to the TypeScript backend's `init`. */
  readonly ts?: TsInitOptions;
}

// Typed by the shared interface both backends implement, never by their own
// modules: the declarations then name no optional package, and type-check with
// only one backend installed.
let active: { readonly name: Backend; readonly module: Frontend } | undefined;

async function start(name: Backend, options: InitOptions): Promise<Backend> {
  // Cleared first, so a failed start leaves nothing answering rather than the
  // backend the caller just asked to replace.
  active = undefined;
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
 * A failed call leaves no backend in use, whatever was in use before it.
 *
 * @returns the backend now in use.
 * @throws if the requested backend cannot start; under `"auto"`, an
 *   `AggregateError` carrying the failure of each backend it tried.
 */
export async function init(options: InitOptions = {}): Promise<Backend> {
  const choice = options.backend ?? "auto";
  if (choice !== "auto") return start(choice, options);
  const failures: unknown[] = [];
  if (typeof WebAssembly === "object") {
    try {
      return await start("wasm", options);
    } catch (err) {
      // Kept for the report if the fallback fails too.
      failures.push(err);
    }
  }
  try {
    return await start("ts", options);
  } catch (err) {
    failures.push(err);
    throw new AggregateError(failures, "no backend could start");
  }
}

/** The backend in use, or `undefined` before {@link init}. */
export function backend(): Backend | undefined {
  return active?.name;
}

function current(): Frontend {
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
