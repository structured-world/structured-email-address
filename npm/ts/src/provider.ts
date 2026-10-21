// Provider registry: a port of the Rust crate's `src/provider.rs`.

import type { ResolvedProviderRule } from "../../shared/src/types.js";
import { toAscii } from "./idna.js";

/** A rule with its domains in canonical (IDNA-ASCII) form. */
export interface Provider {
  readonly domains: readonly string[];
  readonly stripDots: boolean;
  readonly lowercaseLocal: boolean;
  readonly separator: string | undefined;
  readonly freemail: boolean;
}

/** IDNA-ASCII, lowercased; falls back to ASCII lowercasing when IDNA refuses. */
function canonicalDomain(domain: string): string {
  return toAscii(domain) ?? domain.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** Every built-in folds case, uses `+` and is freemail; only the dot policy varies. */
function builtin(domains: readonly string[], stripDots: boolean): Provider {
  return { domains, stripDots, lowercaseLocal: true, separator: "+", freemail: true };
}

/** The built-in providers, written in canonical form already. */
export const BUILTIN: readonly Provider[] = [
  builtin(["gmail.com", "googlemail.com"], true),
  builtin(["outlook.com", "hotmail.com", "live.com", "msn.com"], false),
  builtin(["yahoo.com", "yahoo.co.uk", "yahoo.co.jp"], false),
  builtin(["protonmail.com", "proton.me"], false),
  builtin(["icloud.com", "me.com", "mac.com"], false),
  builtin(["yandex.ru", "yandex.com"], false),
  builtin(["mail.ru"], false),
  builtin(
    ["aol.com", "mail.com", "zoho.com", "gmx.com", "gmx.de", "web.de", "tutanota.com", "tuta.io", "fastmail.com"],
    false,
  ),
];

export function compileProvider(rule: ResolvedProviderRule): Provider {
  return {
    domains: rule.domains.map(canonicalDomain),
    stripDots: rule.stripDots,
    lowercaseLocal: rule.lowercaseLocal,
    separator: rule.subaddressSeparator ?? undefined,
    freemail: rule.freemail,
  };
}

/** The most recently added rule matching `domain`, which is canonicalized once. */
export function lookup(registry: readonly Provider[], domain: string): Provider | undefined {
  const canonical = canonicalDomain(domain);
  for (let i = registry.length - 1; i >= 0; i--) {
    const rule = registry[i]!;
    if (rule.domains.includes(canonical)) return rule;
  }
  return undefined;
}
