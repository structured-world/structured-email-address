// Public API for @structured-world/structured-email-address-ts: the Rust
// crate's pipeline ported to TypeScript. Public Suffix List lookups use the
// Rust crate's binary trie format, in its newest data release, downloaded once
// by @structured-world/structured-public-domains/tiny and cached locally.

import { isLoaded, load } from "@structured-world/structured-public-domains/tiny";

import { frontend } from "../../shared/src/api.js";
import type { Engine, TsInitOptions } from "../../shared/src/types.js";
import { confusableSkeleton as skeleton } from "./confusables.js";
import { parseEmail, type Compiled } from "./email.js";
import { isSmtpMailbox as smtpMailbox } from "./parser.js";
import { BUILTIN, compileProvider } from "./provider.js";

export * from "../../shared/src/public.js";

/** Options for {@link init}. */
export type InitOptions = TsInitOptions;

/**
 * Load the Public Suffix List trie. Must be awaited before any other function.
 * Idempotent; the trie comes from the local cache when it is fresh.
 *
 * By default the trie is the newest structured-public-domains data release,
 * which follows publicsuffix.org daily. The WebAssembly backend embeds the list
 * as of its own release instead, so the two can differ on a suffix the list
 * changed in between, as the two entries of structured-public-domains do.
 *
 * @throws if the trie can be neither read from the cache nor fetched.
 */
export async function init(options: InitOptions = {}): Promise<void> {
  // The loader's default URL, deliberately: it tracks the newest patch release,
  // and a URL pinned to the build-time release would freeze the list until the
  // next release of this package.
  await load(options.psl);
}

/** Whether {@link init} has completed. */
export function isInitialized(): boolean {
  return isLoaded();
}

const engine: Engine<Compiled> = {
  compile: (config) => ({
    config,
    registry: [...(config.builtinProviders ? BUILTIN : []), ...config.providers.map(compileProvider)],
  }),
  parse: parseEmail,
  parseBatch: (inputs, compiled) => inputs.map((input) => parseEmail(input, compiled)),
  isSmtpMailbox: smtpMailbox,
  confusableSkeleton: skeleton,
};

const api = frontend(() => {
  if (!isLoaded()) throw new Error("not initialized: call `await init()` first");
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
