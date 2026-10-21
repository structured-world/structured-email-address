// Post-parse validation: a port of the Rust crate's `src/validate.rs`.

import { isKnownSuffix } from "@structured-world/structured-public-domains/tiny";

import type { ResolvedConfig } from "../../shared/src/types.js";
import { MAX_ADDRESS_LEN, MAX_LABEL_LEN, MAX_LOCAL_PART_LEN, utf8Length } from "./limits.js";
import type { Normalized } from "./normalize.js";
import { domainStr, localPartStr, ParseFailure, type Parsed } from "./parser.js";

function lastLabel(domain: string): string {
  return domain.slice(domain.lastIndexOf(".") + 1);
}

export function validate(parsed: Parsed, normalized: Normalized, config: ResolvedConfig): void {
  const domain = normalized.domain;
  const local = localPartStr(parsed);
  const domainText = domainStr(parsed);
  const localLen = utf8Length(local);

  if (localLen > MAX_LOCAL_PART_LEN) {
    throw new ParseFailure({ kind: { type: "LocalPartTooLong", len: localLen }, position: parsed.localPart.start });
  }

  const total = localLen + 1 + utf8Length(domainText);
  if (total > MAX_ADDRESS_LEN) {
    throw new ParseFailure({ kind: { type: "AddressTooLong", len: total }, position: parsed.localPart.start });
  }

  const isDomainLiteral = domainText.startsWith("[");

  if (!config.allowSingleLabelDomain && !domain.includes(".") && !isDomainLiteral) {
    throw new ParseFailure({ kind: { type: "DomainNoDot" }, position: parsed.domain.start });
  }
  if (isDomainLiteral) return;

  for (const label of domain.split(".")) {
    // The canonical domain is IDNA-ASCII, so length is octets.
    if (label.length > MAX_LABEL_LEN) {
      throw new ParseFailure({
        kind: { type: "DomainLabelTooLong", label, len: label.length },
        position: parsed.domain.start,
      });
    }
  }

  const known =
    config.domainCheck === "syntax" ||
    (config.domainCheck === "tld" ? hasTldLikeSuffix(domain) : isKnownSuffix(domain));
  if (!known) {
    throw new ParseFailure({ kind: { type: "UnknownTld", tld: lastLabel(domain) }, position: parsed.domain.start });
  }
}

/** At least two ASCII letters, or a punycode label with content after `xn--`. */
export function hasTldLikeSuffix(domain: string): boolean {
  const tld = lastLabel(domain);
  if (tld.startsWith("xn--") && tld.length > 4) return true;
  return /^[A-Za-z]{2,}$/.test(tld);
}
