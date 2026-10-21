// The parse pipeline and the address's serialized forms: a port of
// `EmailAddress::parse_with`, `canonical` and `Display` in the Rust crate.

import type { EmailAddress, RawOutcome, ResolvedConfig } from "../../shared/src/types.js";
import { normalize } from "./normalize.js";
import { parse as parseSyntax, ParseFailure } from "./parser.js";
import { lookup, type Provider } from "./provider.js";
import { classify } from "./scope.js";
import { validate } from "./validate.js";

export interface Compiled {
  readonly config: ResolvedConfig;
  /** Built-ins (unless disabled) followed by the caller's rules, canonicalized once. */
  readonly registry: readonly Provider[];
}

export function parseEmail(input: string, { config, registry }: Compiled): RawOutcome {
  try {
    const parsed = parseSyntax(input, config);
    const normalized = normalize(parsed, config, registry);
    validate(parsed, normalized, config);
    const quotedLocal = needsQuoting(normalized.localPart)
      ? `"${escapeLocalPart(normalized.localPart)}"`
      : normalized.localPart;
    const canonical = `${quotedLocal}@${normalized.domain}`;
    const value: EmailAddress = {
      original: input,
      localPart: normalized.localPart,
      ...(normalized.tag !== undefined && { tag: normalized.tag }),
      domain: normalized.domain,
      domainUnicode: normalized.domainUnicode ?? normalized.domain,
      ...(normalized.displayName !== undefined && { displayName: normalized.displayName }),
      ...(normalized.skeleton !== undefined && { skeleton: normalized.skeleton }),
      freemail: lookup(registry, normalized.domain)?.freemail ?? false,
      canonical,
      formatted:
        normalized.displayName !== undefined
          ? `"${escapeDisplayName(normalized.displayName)}" <${canonical}>`
          : canonical,
      domainScope: classify(normalized.domain),
    };
    return { ok: true, value };
  } catch (e) {
    if (e instanceof ParseFailure) return { ok: false, error: e.data };
    throw e;
  }
}

const ATEXT_SPECIALS = "!#$%&'*+-/=?^_`{|}~.";

/** Whether a local part needs quoting: anything outside ASCII atext, or a dot out of place. */
function needsQuoting(local: string): boolean {
  if (local === "") return true;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return true;
  for (const c of local) {
    const code = c.codePointAt(0)!;
    // Non-ASCII needs no quoting per RFC 6531.
    if (code >= 0x80) continue;
    if (/[A-Za-z0-9]/.test(c) || ATEXT_SPECIALS.includes(c)) continue;
    return true;
  }
  return false;
}

/** Backslash-escape `"` and `\`; drop CR and LF so nothing can inject a header. */
function escapeLocalPart(local: string): string {
  return local.replace(/[\r\n]/g, "").replace(/["\\]/g, "\\$&");
}

const escapeDisplayName = escapeLocalPart;
