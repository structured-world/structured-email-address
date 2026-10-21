// Behaviour every backend shares: option validation, the error type and its
// messages, and the public functions built on a backend's engine.

import type {
  Config,
  DomainScope,
  EmailAddress,
  Engine,
  ErrorData,
  ErrorKind,
  ProviderRule,
  RawOutcome,
  ResolvedConfig,
  ResolvedProviderRule,
} from "./types.js";

const BRAND = Symbol.for("@structured-world/structured-email-address/error");

/**
 * A parse or validation failure.
 *
 * `instanceof` holds across backends: each package bundles its own copy of
 * this class, so identity is decided by a registered symbol, not the class.
 */
export class EmailAddressError extends Error {
  /** What went wrong, with the variant's details. */
  readonly kind: ErrorKind;
  /** UTF-16 offset into the input where the failure was detected. */
  readonly position: number;

  constructor(data: ErrorData) {
    super(errorMessage(data.kind, data.position));
    this.name = "EmailAddressError";
    this.kind = data.kind;
    this.position = data.position;
    Object.defineProperty(this, BRAND, { value: true });
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    return typeof value === "object" && value !== null && (value as Record<symbol, unknown>)[BRAND] === true;
  }
}

/** The Rust crate's `Display` text for an error, with a UTF-16 position. */
export function errorMessage(kind: ErrorKind, position: number): string {
  switch (kind.type) {
    case "Empty":
      return "empty input";
    case "MissingAtSign":
      return "missing '@' separator";
    case "EmptyLocalPart":
      return "empty local part";
    case "EmptyDomain":
      return "empty domain";
    case "LocalPartTooLong":
      return `local part too long: ${kind.len} octets (max 64)`;
    case "AddressTooLong":
      return `address too long: ${kind.len} octets (max 254)`;
    case "DomainLabelTooLong":
      return `domain label '${kind.label}' too long: ${kind.len} octets (max 63)`;
    case "InvalidLocalPartChar":
      return `invalid character in local part: '${kind.ch}'`;
    case "InvalidDomainChar":
      return `invalid character in domain: '${kind.ch}'`;
    case "DomainLabelHyphen":
      return "domain label starts or ends with hyphen";
    case "DomainNoDot":
      return "domain has no dot";
    case "UnterminatedQuotedString":
      return "unterminated quoted string";
    case "InvalidQuotedPair":
      return "invalid quoted-pair escape";
    case "UnterminatedComment":
      return "unterminated comment";
    case "UnterminatedDomainLiteral":
      return "unterminated domain literal";
    case "InvalidAddressLiteral":
      return "domain literal is not a valid IPv4 or IPv6 address literal";
    case "IdnaError":
      return `IDNA encoding failed: ${kind.message}`;
    case "UnknownTld":
      return `unknown TLD: .${kind.tld}`;
    case "Unexpected":
      return `unexpected character '${kind.ch}' at position ${position}`;
  }
}

/** Whether the domain is reachable from the public internet. */
export function isGlobalScope(scope: DomainScope): boolean {
  switch (scope.kind) {
    case "global":
      return true;
    case "local":
      return false;
    case "literal":
      return (scope.literal.kind === "ipv4" || scope.literal.kind === "ipv6") && scope.literal.ip === "global";
  }
}

function pick<T extends string>(name: string, value: T | undefined, allowed: readonly T[], fallback: T): T {
  if (value === undefined) return fallback;
  if (!allowed.includes(value)) {
    throw new TypeError(`${name} must be one of ${allowed.map((v) => JSON.stringify(v)).join(", ")}`);
  }
  return value;
}

function flag(name: string, value: boolean | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new TypeError(`${name} must be a boolean`);
  return value;
}

/** Whether `value` is exactly one Unicode scalar value. */
function isOneChar(value: string): boolean {
  const cp = value.codePointAt(0);
  if (cp === undefined || (cp >= 0xd800 && cp <= 0xdfff)) return false;
  return value.length === (cp > 0xffff ? 2 : 1);
}

function separator(name: string, value: unknown): string {
  if (typeof value !== "string" || !isOneChar(value)) {
    throw new TypeError(`${name} must be exactly one character`);
  }
  return value;
}

function resolveProvider(rule: ProviderRule, i: number): ResolvedProviderRule {
  const name = `providers[${i}]`;
  if (!Array.isArray(rule.domains) || rule.domains.some((d) => typeof d !== "string")) {
    throw new TypeError(`${name}.domains must be an array of strings`);
  }
  const sep = rule.subaddressSeparator;
  return {
    domains: [...rule.domains],
    stripDots: flag(`${name}.stripDots`, rule.stripDots, false),
    lowercaseLocal: flag(`${name}.lowercaseLocal`, rule.lowercaseLocal, false),
    subaddressSeparator: sep === null ? null : separator(`${name}.subaddressSeparator`, sep ?? "+"),
    freemail: flag(`${name}.freemail`, rule.freemail, false),
  };
}

/** Validate options and fill the defaults the Rust crate's `Config::default` uses. */
export function resolveConfig(config: Config = {}): ResolvedConfig {
  return {
    strictness: pick("strictness", config.strictness, ["strict", "standard", "lax"], "standard"),
    dotPolicy: pick("dotPolicy", config.dotPolicy, ["preserve", "gmailOnly", "always"], "preserve"),
    casePolicy: pick("casePolicy", config.casePolicy, ["domain", "all", "preserve"], "domain"),
    domainCheck: pick("domainCheck", config.domainCheck, ["syntax", "psl", "tld"], "syntax"),
    subaddress: pick("subaddress", config.subaddress, ["preserve", "strip"], "preserve"),
    subaddressSeparator: separator("subaddressSeparator", config.subaddressSeparator ?? "+"),
    checkConfusables: flag("checkConfusables", config.checkConfusables, false),
    addressLiteral: pick("addressLiteral", config.addressLiteral, ["reject", "routable", "rfc5321"], "reject"),
    allowDisplayName: flag("allowDisplayName", config.allowDisplayName, false),
    allowSingleLabelDomain: flag("allowSingleLabelDomain", config.allowSingleLabelDomain, false),
    allowQuotedLocalPart: flag("allowQuotedLocalPart", config.allowQuotedLocalPart, false),
    providerAware: flag("providerAware", config.providerAware, false),
    builtinProviders: flag("builtinProviders", config.builtinProviders, true),
    providers: (config.providers ?? []).map(resolveProvider),
  };
}

/** Offset of the first unpaired surrogate, or -1 if `input` is well-formed UTF-16. */
export function loneSurrogate(input: string): number {
  for (let i = 0; i < input.length; i++) {
    const unit = input.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = input.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      return i;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return i;
  }
  return -1;
}

const REPLACEMENT_CHARACTER = String.fromCharCode(0xfffd);

/**
 * Replace unpaired surrogates with U+FFFD, the conversion a JavaScript string
 * undergoes on its way into Rust, so both backends read the same text.
 */
export function toWellFormed(input: string): string {
  if (loneSurrogate(input) === -1) return input;
  let out = "";
  for (const ch of input) {
    const unit = ch.charCodeAt(0);
    out += ch.length === 1 && unit >= 0xd800 && unit <= 0xdfff ? REPLACEMENT_CHARACTER : ch;
  }
  return out;
}

/** One outcome of {@link Parser.parseBatch}. */
export type ParseOutcome =
  | { readonly ok: true; readonly value: EmailAddress }
  | { readonly ok: false; readonly error: EmailAddressError };

/** Parsing functions bound to one configuration, prepared once. */
export interface Parser {
  /** Parse and validate one address. @throws {EmailAddressError} */
  parse(input: string): EmailAddress;
  /** Parse many addresses; one outcome per input, in order. */
  parseBatch(inputs: readonly string[]): ParseOutcome[];
}

/** The functions a backend package exports, built on its engine. */
export interface Frontend {
  createParser(config?: Config): Parser;
  parse(input: string, config?: Config): EmailAddress;
  parseBatch(inputs: readonly string[], config?: Config): ParseOutcome[];
  isSmtpMailbox(input: string): boolean;
  confusableSkeleton(input: string): string;
}

/**
 * A string JavaScript can hold but Rust cannot: an unpaired surrogate. It is
 * refused at its own offset rather than silently replaced, so neither backend
 * accepts an address that is not the text the caller passed.
 */
function surrogateError(input: string): ErrorData | undefined {
  const at = loneSurrogate(input);
  if (at === -1) return undefined;
  return { kind: { type: "Unexpected", ch: input.charAt(at) }, position: at };
}

function outcome(raw: RawOutcome): ParseOutcome {
  return raw.ok ? raw : { ok: false, error: new EmailAddressError(raw.error) };
}

/** Build the public functions on a backend's engine, obtained lazily. */
export function frontend<C>(engine: () => Engine<C>): Frontend {
  const bind = (compiled: C): Parser => {
    return {
      parse(input) {
        const bad = surrogateError(input);
        if (bad !== undefined) throw new EmailAddressError(bad);
        const raw = engine().parse(input, compiled);
        if (!raw.ok) throw new EmailAddressError(raw.error);
        return raw.value;
      },
      parseBatch(inputs) {
        const results: (ParseOutcome | undefined)[] = new Array(inputs.length);
        const clean: string[] = [];
        const slots: number[] = [];
        inputs.forEach((input, i) => {
          const bad = surrogateError(input);
          if (bad === undefined) {
            clean.push(input);
            slots.push(i);
          } else {
            results[i] = { ok: false, error: new EmailAddressError(bad) };
          }
        });
        if (clean.length > 0) {
          const raws = engine().parseBatch(clean, compiled);
          // One outcome per input is the engine's contract; a mismatch would
          // otherwise surface as undefined entries or silently dropped outcomes.
          if (raws.length !== clean.length) {
            throw new Error(`backend returned ${raws.length} outcomes for ${clean.length} inputs`);
          }
          raws.forEach((raw, j) => {
            results[slots[j]!] = outcome(raw);
          });
        }
        return results as ParseOutcome[];
      },
    };
  };
  // A one-shot call frees its configuration on the way out, rather than leaving
  // it to the garbage collector, which cannot run inside a synchronous loop.
  const oneShot = <T>(config: Config | undefined, run: (parser: Parser) => T): T => {
    const e = engine();
    const compiled = e.compile(resolveConfig(config));
    try {
      return run(bind(compiled));
    } finally {
      e.release?.(compiled);
    }
  };
  return {
    createParser: (config) => bind(engine().compile(resolveConfig(config))),
    parse: (input, config) => oneShot(config, (parser) => parser.parse(input)),
    parseBatch: (inputs, config) => oneShot(config, (parser) => parser.parseBatch(inputs)),
    isSmtpMailbox: (input) => engine().isSmtpMailbox(input),
    confusableSkeleton: (input) => engine().confusableSkeleton(toWellFormed(input)),
  };
}
