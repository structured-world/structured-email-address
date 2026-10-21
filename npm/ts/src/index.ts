// Public API for @structured-world/structured-email-address-ts: the Rust
// crate's pipeline ported to TypeScript. Public Suffix List lookups use the
// same binary trie as the Rust crate, downloaded once by
// @structured-world/structured-public-domains/tiny and cached locally.

import { isLoaded, load } from "@structured-world/structured-public-domains/tiny";

import { frontend } from "../../shared/src/api.js";
import type { Engine, TsInitOptions } from "../../shared/src/types.js";
import { PSL_VERSION } from "../generated/psl-version.js";
import { confusableSkeleton as skeleton } from "./confusables.js";
import { parseEmail, type Compiled } from "./email.js";
import { isSmtpMailbox as smtpMailbox } from "./parser.js";
import { BUILTIN, compileProvider } from "./provider.js";

export * from "../../shared/src/public.js";

/** Options for {@link init}. */
export type InitOptions = TsInitOptions;

// The loader's own default follows the newest 0.0.x release on the CDN, while
// the WebAssembly backend embeds the trie of one release. Pinning the release
// this package was built and checked against keeps both on the same list.
const PSL_URL = `https://cdn.jsdelivr.net/npm/@structured-world/structured-public-domains@${PSL_VERSION}/dist/psl.bin`;

/**
 * Load the Public Suffix List trie. Must be awaited before any other function.
 * Idempotent; the trie comes from the local cache when it is fresh.
 *
 * By default the trie is the `psl.bin` of the structured-public-domains release
 * this package was built against, the same list the WebAssembly backend embeds.
 *
 * @throws if the trie can be neither read from the cache nor fetched.
 */
export async function init(options: InitOptions = {}): Promise<void> {
  await load({ ...options.psl, url: options.psl?.url ?? PSL_URL });
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
