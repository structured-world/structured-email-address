// Normalization: a port of the Rust crate's `src/normalize.rs`.

import type { ResolvedConfig } from "../../shared/src/types.js";
import { confusableSkeleton } from "./confusables.js";
import { toAsciiStrict, toUnicode } from "./idna.js";
import { domainStr, isIpAddressLiteral, localPartStr, ParseFailure, type Parsed } from "./parser.js";
import { BUILTIN, lookup, type Provider } from "./provider.js";

export interface Normalized {
  readonly localPart: string;
  readonly tag: string | undefined;
  readonly domain: string;
  readonly domainUnicode: string | undefined;
  readonly displayName: string | undefined;
  readonly skeleton: string | undefined;
}

export function normalize(parsed: Parsed, config: ResolvedConfig, registry: readonly Provider[]): Normalized {
  const local = localPartStr(parsed);
  const domainText = domainStr(parsed);
  const isQuoted = local.startsWith('"') && local.endsWith('"');

  const unquoted = isQuoted ? unescapeQuotedString(local.slice(1, -1)) : local;
  const nfcLocal = unquoted.normalize("NFC");
  const nfcDomain = domainText.normalize("NFC");

  let canonicalDomain: string;
  if (nfcDomain.startsWith("[")) {
    const inner = nfcDomain.startsWith("[") && nfcDomain.endsWith("]") ? nfcDomain.slice(1, -1) : nfcDomain;
    canonicalDomain = isIpAddressLiteral(inner) ? nfcDomain.toLowerCase() : nfcDomain;
  } else {
    const ascii = toAsciiStrict(nfcDomain);
    if (ascii === undefined) {
      // `idna::Errors` carries no detail; its Debug form, `Errors`, is what Rust prints.
      throw new ParseFailure({
        kind: { type: "IdnaError", message: `${nfcDomain}: Errors` },
        position: parsed.domain.start,
      });
    }
    canonicalDomain = ascii;
  }

  const provider = config.providerAware ? lookup(registry, canonicalDomain) : undefined;

  const lowercaseLocal = provider !== undefined && !isQuoted ? provider.lowercaseLocal : config.casePolicy === "all";
  const casedLocal = lowercaseLocal ? nfcLocal.toLowerCase() : nfcLocal;

  let tag: string | undefined;
  let localAfterDots: string;
  if (isQuoted) {
    localAfterDots = casedLocal;
  } else {
    const sep = provider !== undefined ? provider.separator : config.subaddressSeparator;
    let base = casedLocal;
    if (sep !== undefined) {
      const at = casedLocal.indexOf(sep);
      if (at > 0) {
        base = casedLocal.slice(0, at);
        tag = casedLocal.slice(at + sep.length);
      }
    }

    const localAfterTag =
      config.subaddress === "strip" || tag === undefined || sep === undefined ? base : `${base}${sep}${tag}`;

    let strip: boolean;
    if (provider !== undefined) strip = provider.stripDots;
    else if (config.dotPolicy === "always") strip = true;
    else if (config.dotPolicy === "gmailOnly") strip = lookup(BUILTIN, canonicalDomain)?.stripDots ?? false;
    else strip = false;
    localAfterDots = strip ? localAfterTag.replaceAll(".", "") : localAfterTag;
  }

  let domainUnicode: string | undefined;
  if (canonicalDomain.split(".").some((label) => label.startsWith("xn--"))) {
    const unicode = toUnicode(canonicalDomain);
    if (!unicode.error && unicode.domain !== canonicalDomain) domainUnicode = unicode.domain;
  }

  const skeleton = config.checkConfusables ? confusableSkeleton(localAfterDots) : undefined;

  const displayName =
    parsed.displayName !== undefined
      ? unescapeQuotedString(parsed.input.slice(parsed.displayName.start, parsed.displayName.end))
      : undefined;

  return { localPart: localAfterDots, tag, domain: canonicalDomain, domainUnicode, displayName, skeleton };
}

/** Remove quoted-pair backslashes and collapse FWS (CRLF + WSP) to one space. */
function unescapeQuotedString(s: string): string {
  let out = "";
  const chars = Array.from(s);
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i]!;
    if (c === "\\") {
      // Keep a trailing backslash with nothing to escape.
      out += i + 1 < chars.length ? chars[++i]! : c;
    } else if (c === "\r") {
      if (chars[i + 1] === "\n") {
        i++;
        while (chars[i + 1] === " " || chars[i + 1] === "\t") i++;
        out += " ";
      }
      // A bare CR is dropped.
    } else if (c !== "\n") {
      out += c;
    }
  }
  return out;
}
