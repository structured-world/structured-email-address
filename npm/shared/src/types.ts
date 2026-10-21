// The public types every backend shares. Each package bundles this file, so
// the shapes are identical whichever backend a consumer installs.

/** How strictly to read the RFC grammar. */
export type Strictness =
  /** RFC 5321 envelope: dot-atom only, no comments, no quoted strings, no obs-*. */
  | "strict"
  /** RFC 5322 header grammar, including quoted strings, comments and CFWS. */
  | "standard"
  /** `standard` plus the obsolete RFC 5322 §4.4 forms obs-local-part and obs-domain. */
  | "lax";

/** What to do with dots in the local part. */
export type DotPolicy =
  /** Keep them. */
  | "preserve"
  /** Strip them only for the built-in providers that ignore them (Gmail, Googlemail). */
  | "gmailOnly"
  /** Always strip them. */
  | "always";

/** What to do with letter case. */
export type CasePolicy =
  /** Lowercase the domain only; the local part is case-sensitive per RFC 5321. */
  | "domain"
  /** Lowercase the local part and the domain. */
  | "all"
  /** Keep the local part's case; the domain is still lowercased. */
  | "preserve";

/** Which RFC 5321 §4.1.3 `address-literal` spellings the domain may take. */
export type AddressLiteral =
  /** Refuse every `[...]` domain literal. */
  | "reject"
  /** Accept an IPv4 dotted quad or an `IPv6:`-tagged address, refusing zero-padded octets. */
  | "routable"
  /** Accept every alternative the grammar names, `General-address-literal` included. */
  | "rfc5321";

/** How to validate the domain beyond its syntax. */
export type DomainCheck =
  /** Syntax only. */
  | "syntax"
  /** Require a suffix listed in the Public Suffix List. */
  | "psl"
  /** Require a TLD-like final label (two or more ASCII letters, or punycode). */
  | "tld";

/** Whether the `+tag` subaddress stays in the canonical form. */
export type SubaddressPolicy = "preserve" | "strip";

/** Normalization rule for one mail provider. */
export interface ProviderRule {
  /** Domains the provider owns; matched after IDNA canonicalization. */
  readonly domains: readonly string[];
  /** Whether dots in the local part are insignificant. Default `false`. */
  readonly stripDots?: boolean;
  /** Whether the local part is case-insensitive. Default `false`. */
  readonly lowercaseLocal?: boolean;
  /** The subaddress separator (one character), or `null` for none. Default `"+"`. */
  readonly subaddressSeparator?: string | null;
  /** Whether the provider is free webmail. Default `false`. */
  readonly freemail?: boolean;
}

/** Parsing options. Every field is optional; omitted ones take the Rust crate's defaults. */
export interface Config {
  readonly strictness?: Strictness;
  readonly dotPolicy?: DotPolicy;
  readonly casePolicy?: CasePolicy;
  readonly domainCheck?: DomainCheck;
  readonly subaddress?: SubaddressPolicy;
  /** One character. Default `"+"`. */
  readonly subaddressSeparator?: string;
  /** Compute the anti-homoglyph skeleton of the local part. */
  readonly checkConfusables?: boolean;
  readonly addressLiteral?: AddressLiteral;
  /** Accept `"Name" <user@example.com>`. */
  readonly allowDisplayName?: boolean;
  /** Accept a domain without a dot, like `admin@printer`. */
  readonly allowSingleLabelDomain?: boolean;
  /** Under `strict`, accept a quoted local part (RFC 5321 `Quoted-string`). */
  readonly allowQuotedLocalPart?: boolean;
  /** Let a matched provider rule override the dot, case and separator policies. */
  readonly providerAware?: boolean;
  /** Start from the built-in provider registry. Default `true`. */
  readonly builtinProviders?: boolean;
  /** Extra provider rules; later rules win over earlier ones and over built-ins. */
  readonly providers?: readonly ProviderRule[];
}

/** How far an IP address reaches. */
export type IpScope = "global" | "local";

/** Which address literal, and how far it reaches. */
export type LiteralScope =
  | { readonly kind: "ipv4"; readonly ip: IpScope }
  | { readonly kind: "ipv6"; readonly ip: IpScope }
  | { readonly kind: "general" };

/** Whether a domain is resolvable by the global DNS, local to a network, or a literal. */
export type DomainScope =
  | { readonly kind: "global" }
  | { readonly kind: "local" }
  | { readonly kind: "literal"; readonly literal: LiteralScope };

/** A parsed, validated and normalized address. */
export interface EmailAddress {
  /** The input, exactly as given. */
  readonly original: string;
  /** The canonical local part, after normalization. */
  readonly localPart: string;
  /** The subaddress tag, extracted whatever the subaddress policy. */
  readonly tag?: string;
  /** The canonical domain: IDNA-ASCII and lowercased, or the bracketed literal. */
  readonly domain: string;
  /** The domain in Unicode form, for display only. */
  readonly domainUnicode: string;
  /** The display name, when parsed from `name-addr`. */
  readonly displayName?: string;
  /** The confusable skeleton of the local part, when `checkConfusables` is set. */
  readonly skeleton?: string;
  /** Whether the domain belongs to a free webmail provider in the registry. */
  readonly freemail: boolean;
  /** `localPart@domain`, quoted where the local part needs it. */
  readonly canonical: string;
  /** The canonical address with its display name, `"Name" <local@domain>`. */
  readonly formatted: string;
  readonly domainScope: DomainScope;
}

/** What went wrong; `type` names the Rust crate's `ErrorKind` variant. */
export type ErrorKind =
  | { readonly type: "Empty" }
  | { readonly type: "MissingAtSign" }
  | { readonly type: "EmptyLocalPart" }
  | { readonly type: "EmptyDomain" }
  | { readonly type: "LocalPartTooLong"; readonly len: number }
  | { readonly type: "AddressTooLong"; readonly len: number }
  | { readonly type: "DomainLabelTooLong"; readonly label: string; readonly len: number }
  | { readonly type: "InvalidLocalPartChar"; readonly ch: string }
  | { readonly type: "InvalidDomainChar"; readonly ch: string }
  | { readonly type: "DomainLabelHyphen" }
  | { readonly type: "DomainNoDot" }
  | { readonly type: "UnterminatedQuotedString" }
  | { readonly type: "InvalidQuotedPair" }
  | { readonly type: "UnterminatedComment" }
  | { readonly type: "UnterminatedDomainLiteral" }
  | { readonly type: "InvalidAddressLiteral" }
  | { readonly type: "IdnaError"; readonly message: string }
  | { readonly type: "UnknownTld"; readonly tld: string }
  | { readonly type: "Unexpected"; readonly ch: string };

/** A failure as the backends report it, before it becomes an `EmailAddressError`. */
export interface ErrorData {
  readonly kind: ErrorKind;
  /** UTF-16 offset into the input. */
  readonly position: number;
}

/** One outcome of a backend parse. */
export type RawOutcome =
  | { readonly ok: true; readonly value: EmailAddress }
  | { readonly ok: false; readonly error: ErrorData };

/** `Config` with every field present and validated. */
export interface ResolvedConfig {
  readonly strictness: Strictness;
  readonly dotPolicy: DotPolicy;
  readonly casePolicy: CasePolicy;
  readonly domainCheck: DomainCheck;
  readonly subaddress: SubaddressPolicy;
  readonly subaddressSeparator: string;
  readonly checkConfusables: boolean;
  readonly addressLiteral: AddressLiteral;
  readonly allowDisplayName: boolean;
  readonly allowSingleLabelDomain: boolean;
  readonly allowQuotedLocalPart: boolean;
  readonly providerAware: boolean;
  readonly builtinProviders: boolean;
  readonly providers: readonly ResolvedProviderRule[];
}

/** `ProviderRule` with every field present. */
export interface ResolvedProviderRule {
  readonly domains: readonly string[];
  readonly stripDots: boolean;
  readonly lowercaseLocal: boolean;
  readonly subaddressSeparator: string | null;
  readonly freemail: boolean;
}

/** Options for the WebAssembly backend's `init`. */
export interface WasmInitOptions {
  /**
   * A precompiled `WebAssembly.Module` or the module's bytes, for environments
   * that compile WebAssembly elsewhere (a worker, a cache). Defaults to the
   * embedded module.
   *
   * Spelled without the DOM library's names, so a Node consumer type-checks
   * these declarations without it: `BufferSource` is `ArrayBuffer |
   * ArrayBufferView`, and `WebAssembly.Module` is an empty interface, which is
   * what `object` already says.
   */
  readonly module?: ArrayBuffer | ArrayBufferView | object;
}

/**
 * How the TypeScript backend fetches and caches the Public Suffix List trie:
 * the options of `load` in `@structured-world/structured-public-domains/tiny`.
 * Spelled out here so the default package's declarations name no optional
 * dependency; the TypeScript backend passes it to `load`, which checks it.
 */
export interface PslLoadOptions {
  /** Where to fetch `psl.bin` from. Defaults to the package's jsDelivr URL. */
  readonly url?: string;
  /** Fetch implementation, for proxies and tests. Defaults to the global `fetch`. */
  readonly fetch?: typeof fetch;
  /** Keep a persistent local copy. Default `true`. */
  readonly cache?: boolean;
  /** How long the local copy stays fresh, in milliseconds. Default 24 hours. */
  readonly cacheTtlMs?: number;
  /** Node only: the directory for the cache file. */
  readonly cacheDir?: string;
  /** Fetch again even when a fresh copy is loaded or cached. */
  readonly force?: boolean;
}

/** Options for the TypeScript backend's `init`. */
export interface TsInitOptions {
  /** Where and how the Public Suffix List trie is fetched and cached. */
  readonly psl?: PslLoadOptions;
}

/** What a backend implements; the public functions are built on top of it. */
export interface Engine<Compiled> {
  /** Prepare a resolved config once for many parses. */
  compile(config: ResolvedConfig): Compiled;
  /**
   * Free what `compile` allocated outside the JavaScript heap, as soon as a
   * one-shot call is done with it. A parser from `createParser` is left to the
   * garbage collector instead, since its lifetime is the caller's.
   */
  release?(compiled: Compiled): void;
  parse(input: string, compiled: Compiled): RawOutcome;
  parseBatch(inputs: readonly string[], compiled: Compiled): RawOutcome[];
  isSmtpMailbox(input: string): boolean;
  confusableSkeleton(input: string): string;
}
