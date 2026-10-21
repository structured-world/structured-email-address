// RFC 5321/5322/6531 email address parser: a port of the Rust crate's
// `src/parser.rs`, kept in step with it by the parity suite. Grammar
// references and the reasoning behind each rule live there; comments here
// cover only what the port itself has to account for.
//
// Offsets are UTF-16 code units, the unit JavaScript strings index by, where
// the Rust parser counts bytes. Every branch reads whole code points, so the
// two report the same character at the same logical position.

import type { AddressLiteral, ErrorData, ErrorKind, ResolvedConfig, Strictness } from "../../shared/src/types.js";
import { parseIpv4, parseIpv6, type Ipv4, type Ipv6 } from "./net.js";
import { MAX_ADDRESS_LEN, MAX_LABEL_LEN, MAX_LOCAL_PART_LEN, utf8Length } from "./limits.js";

const MAX_RECURSION_DEPTH = 128;

/** Which quoted-string alphabet a `"..."` run is read against. */
const enum Quoted {
  Smtp,
  Header,
  Obsolete,
}

function headerQuoted(allowObs: boolean): Quoted {
  return allowObs ? Quoted.Obsolete : Quoted.Header;
}

/** A UTF-16 range into the input. */
export interface Span {
  readonly start: number;
  readonly end: number;
}

/** Raw parse result. */
export interface Parsed {
  readonly input: string;
  readonly displayName: Span | undefined;
  readonly localPart: Span;
  readonly domain: Span;
  /** The local part with obs-mode CFWS stripped, when there was any. */
  readonly localPartClean: string | undefined;
  /** The domain with obs-mode CFWS stripped, when there was any. */
  readonly domainClean: string | undefined;
}

export function localPartStr(p: Parsed): string {
  return p.localPartClean ?? p.input.slice(p.localPart.start, p.localPart.end);
}

export function domainStr(p: Parsed): string {
  return p.domainClean ?? p.input.slice(p.domain.start, p.domain.end);
}

/** Thrown inside the parser and caught at its entry points. */
export class ParseFailure {
  constructor(readonly data: ErrorData) {}
}

function fail(kind: ErrorKind, position: number): never {
  throw new ParseFailure({ kind, position });
}

const END = -1;

class Parser {
  pos = 0;

  constructor(readonly input: string) {}

  /** The next code point, or {@link END}. */
  peek(): number {
    return this.pos < this.input.length ? this.input.codePointAt(this.pos)! : END;
  }

  advance(): number {
    const ch = this.peek();
    if (ch !== END) this.pos += ch > 0xffff ? 2 : 1;
    return ch;
  }

  eat(expected: number): boolean {
    if (this.peek() === expected) {
      this.pos += expected > 0xffff ? 2 : 1;
      return true;
    }
    return false;
  }

  atEnd(): boolean {
    return this.pos >= this.input.length;
  }

  fail(kind: ErrorKind): never {
    fail(kind, this.pos);
  }

  /** The unit at `pos + offset`, or NaN past the end. */
  unitAt(offset: number): number {
    return this.input.charCodeAt(this.pos + offset);
  }
}

const ch = (c: string): number => c.codePointAt(0)!;
const QUOTE = ch('"');
const BACKSLASH = ch("\\");
const AT = ch("@");
const DOT = ch(".");
const LT = ch("<");
const GT = ch(">");
const LPAREN = ch("(");
const RPAREN = ch(")");
const LBRACKET = ch("[");
const RBRACKET = ch("]");
const HYPHEN = ch("-");
const SPACE = 0x20;
const TAB = 0x09;
const CR = 0x0d;
const LF = 0x0a;

const str = (cp: number): string => (cp === END ? "\0" : String.fromCodePoint(cp));

/**
 * Rust's `str::trim_end`, which strips the Unicode `White_Space` property.
 * `String.prototype.trimEnd` is a different set: it adds U+FEFF and lacks U+0085.
 */
const TRAILING_WHITE_SPACE = /\p{White_Space}+$/u;

/** ASCII SMTP identity check sharing the parser's strict grammar. */
export function isSmtpMailbox(input: string): boolean {
  // ASCII only, so UTF-16 units and the Rust bytes count the same below.
  for (let i = 0; i < input.length; i++) if (input.charCodeAt(i) >= 0x80) return false;
  if (input.length === 0 || input.length > MAX_ADDRESS_LEN) return false;
  try {
    const parser = new Parser(input);
    const [local] = parseLocalPart(parser, "strict", true);
    if (local.end - local.start > MAX_LOCAL_PART_LEN || !parser.eat(AT)) return false;
    const [domain] = parseDomain(parser, "strict", "rfc5321");
    if (!parser.atEnd()) return false;
    const text = input.slice(domain.start, domain.end);
    if (!text.startsWith("[")) {
      for (const label of text.split(".")) if (label.length > MAX_LABEL_LEN) return false;
    }
    return true;
  } catch (e) {
    if (e instanceof ParseFailure) return false;
    throw e;
  }
}

/** Parse an address against the grammar the config selects. @throws {ParseFailure} */
export function parse(input: string, config: ResolvedConfig): Parsed {
  const strictness = config.strictness;
  const strict = strictness === "strict";
  if (input.length === 0) fail({ type: "Empty" }, 0);

  const parser = new Parser(input);
  const allowObs = strictness === "lax";

  if (!strict) skipCfws(parser, 0);

  const displayName = config.allowDisplayName ? tryParseDisplayName(parser, allowObs) : undefined;

  const isAngle = displayName !== undefined || parser.peek() === LT;
  if (isAngle) parser.eat(LT);

  if (!strict) skipCfws(parser, 0);
  const [localPart, localPartClean] = parseLocalPart(parser, strictness, config.allowQuotedLocalPart);
  if (!strict) skipCfws(parser, 0);
  if (!parser.eat(AT)) parser.fail({ type: "MissingAtSign" });
  if (!strict) skipCfws(parser, 0);
  const [domain, domainClean] = parseDomain(parser, strictness, config.addressLiteral);

  if (isAngle) {
    if (!strict) skipCfws(parser, 0);
    if (!parser.eat(GT)) parser.fail({ type: "Unexpected", ch: str(parser.peek()) });
  }

  if (!strict) skipCfws(parser, 0);

  if (!parser.atEnd()) parser.fail({ type: "Unexpected", ch: str(parser.peek()) });

  return { input, displayName, localPart, domain, localPartClean, domainClean };
}

function tryParseDisplayName(parser: Parser, allowObs: boolean): Span | undefined {
  const save = parser.pos;

  if (parser.peek() === QUOTE) {
    const start = parser.pos;
    if (!tryQuotedString(parser, headerQuoted(allowObs))) {
      parser.pos = save;
      return undefined;
    }
    const end = parser.pos;
    skipCfws(parser, 0);
    if (parser.peek() === LT) return { start: start + 1, end: end - 1 };
    parser.pos = save;
    return undefined;
  }

  const start = parser.pos;
  let foundContent = false;
  for (;;) {
    const c = parser.peek();
    if (c === LT && foundContent) {
      const name = parser.input.slice(start, parser.pos);
      return { start, end: start + name.replace(TRAILING_WHITE_SPACE, "").length };
    }
    if (c === AT || c === GT) {
      parser.pos = save;
      return undefined;
    }
    if (c === END || (c < 0x20 && c !== TAB)) {
      parser.pos = save;
      return undefined;
    }
    foundContent = true;
    parser.advance();
  }
}

function parseLocalPart(
  parser: Parser,
  strictness: Strictness,
  quotedLocalPart: boolean,
): [Span, string | undefined] {
  const start = parser.pos;
  const allowObs = strictness === "lax";

  if (parser.peek() === QUOTE) {
    if (strictness === "strict") {
      if (!quotedLocalPart) parser.fail({ type: "InvalidLocalPartChar", ch: '"' });
      parseQuotedString(parser, Quoted.Smtp);
      return [{ start, end: parser.pos }, undefined];
    }
    if (!allowObs) {
      parseQuotedString(parser, Quoted.Header);
      return [{ start, end: parser.pos }, undefined];
    }
  }

  const clean = parseDotAtomLocal(parser, allowObs);
  return [{ start, end: parser.pos }, clean];
}

function parseDotAtomLocal(parser: Parser, allowObs: boolean): string | undefined {
  if (!allowObs) {
    if (!eatAtextRun(parser)) {
      const c = parser.peek();
      if (c !== END && c !== AT) parser.fail({ type: "InvalidLocalPartChar", ch: str(c) });
      parser.fail({ type: "EmptyLocalPart" });
    }
    for (;;) {
      if (!parser.eat(DOT)) break;
      if (!eatAtextRun(parser)) parser.fail({ type: "EmptyLocalPart" });
    }
    return undefined;
  }

  let clean: string | undefined;
  const outerStart = parser.pos;

  if (!eatAtextRun(parser) && !tryQuotedString(parser, headerQuoted(allowObs))) {
    const c = parser.peek();
    if (c !== END && c !== AT) parser.fail({ type: "InvalidLocalPartChar", ch: str(c) });
    parser.fail({ type: "EmptyLocalPart" });
  }

  for (;;) {
    const lastCleanEnd = parser.pos;
    const save = parser.pos;
    skipCfws(parser, 0);
    const hadCfwsBeforeDot = parser.pos > lastCleanEnd;
    if (!parser.eat(DOT)) {
      parser.pos = save;
      break;
    }
    if (hadCfwsBeforeDot && clean === undefined) clean = parser.input.slice(outerStart, lastCleanEnd);
    skipCfws(parser, 0);
    if (clean === undefined && parser.pos > lastCleanEnd + 1) clean = parser.input.slice(outerStart, lastCleanEnd);
    const atomStart = parser.pos;
    if (!eatAtextRun(parser) && !tryQuotedString(parser, headerQuoted(allowObs))) {
      parser.fail({ type: "EmptyLocalPart" });
    }
    if (clean !== undefined) clean += "." + parser.input.slice(atomStart, parser.pos);
  }

  return clean;
}

function eatAtextRun(parser: Parser): boolean {
  const start = parser.pos;
  while (isAtext(parser.peek())) parser.advance();
  return parser.pos > start;
}

function parseQuotedString(parser: Parser, flavor: Quoted): void {
  if (!parser.eat(QUOTE)) parser.fail({ type: "UnterminatedQuotedString" });

  for (;;) {
    const c = parser.peek();
    if (c === QUOTE) {
      parser.advance();
      return;
    }
    if (c === BACKSLASH) {
      parser.advance();
      const escaped = parser.advance();
      if (escaped === END || !isQuotedPairChar(escaped, flavor)) parser.fail({ type: "InvalidQuotedPair" });
      continue;
    }
    if (c === END) parser.fail({ type: "UnterminatedQuotedString" });
    if (isQtext(c, flavor)) {
      parser.advance();
      continue;
    }
    if (flavor !== Quoted.Smtp && (isWsp(c) || c === CR)) {
      if (!tryEatFws(parser)) parser.fail({ type: "InvalidLocalPartChar", ch: "\r" });
      continue;
    }
    parser.fail({ type: "InvalidLocalPartChar", ch: str(c) });
  }
}

function tryQuotedString(parser: Parser, flavor: Quoted): boolean {
  if (parser.peek() !== QUOTE) return false;
  const save = parser.pos;
  try {
    parseQuotedString(parser, flavor);
    return true;
  } catch (e) {
    if (!(e instanceof ParseFailure)) throw e;
    parser.pos = save;
    return false;
  }
}

function parseDomain(
  parser: Parser,
  strictness: Strictness,
  addressLiteral: AddressLiteral,
): [Span, string | undefined] {
  const start = parser.pos;

  if (parser.peek() === LBRACKET) {
    if (addressLiteral === "reject") parser.fail({ type: "InvalidDomainChar", ch: "[" });
    parseDomainLiteral(parser, addressLiteral);
    return [{ start, end: parser.pos }, undefined];
  }

  const clean = parseDotAtomDomain(parser, strictness === "lax");
  return [{ start, end: parser.pos }, clean];
}

function parseDotAtomDomain(parser: Parser, allowObs: boolean): string | undefined {
  if (!allowObs) {
    parseDomainLabel(parser);
    while (parser.eat(DOT)) parseDomainLabel(parser);
    return undefined;
  }

  let clean: string | undefined;
  const outerStart = parser.pos;

  parseDomainLabel(parser);

  for (;;) {
    const lastCleanEnd = parser.pos;
    const save = parser.pos;
    skipCfws(parser, 0);
    const hadCfwsBeforeDot = parser.pos > lastCleanEnd;
    if (!parser.eat(DOT)) {
      parser.pos = save;
      break;
    }
    if (hadCfwsBeforeDot && clean === undefined) clean = parser.input.slice(outerStart, lastCleanEnd);
    skipCfws(parser, 0);
    if (clean === undefined && parser.pos > lastCleanEnd + 1) clean = parser.input.slice(outerStart, lastCleanEnd);
    const labelStart = parser.pos;
    parseDomainLabel(parser);
    if (clean !== undefined) clean += "." + parser.input.slice(labelStart, parser.pos);
  }

  return clean;
}

function parseDomainLabel(parser: Parser): void {
  const first = parser.peek();
  if (isAsciiAlnum(first) || isNonAscii(first)) parser.advance();
  else if (first === HYPHEN) parser.fail({ type: "DomainLabelHyphen" });
  else parser.fail({ type: "EmptyDomain" });

  let lastWasHyphen = false;
  for (;;) {
    const c = parser.peek();
    if (isAsciiAlnum(c) || isNonAscii(c)) {
      lastWasHyphen = false;
      parser.advance();
    } else if (c === HYPHEN) {
      lastWasHyphen = true;
      parser.advance();
    } else {
      break;
    }
  }

  if (lastWasHyphen) parser.fail({ type: "DomainLabelHyphen" });
}

function parseDomainLiteral(parser: Parser, policy: AddressLiteral): void {
  const open = parser.pos;
  if (!parser.eat(LBRACKET)) parser.fail({ type: "UnterminatedDomainLiteral" });
  const contentStart = parser.pos;
  for (;;) {
    const c = parser.peek();
    if (c === RBRACKET) {
      const content = parser.input.slice(contentStart, parser.pos);
      parser.advance();
      if (isAddressLiteral(content, policy)) return;
      fail({ type: "InvalidAddressLiteral" }, open);
    }
    if (c === BACKSLASH) {
      parser.advance();
      if (parser.advance() === END) parser.fail({ type: "UnterminatedDomainLiteral" });
      continue;
    }
    if (c === END) parser.fail({ type: "UnterminatedDomainLiteral" });
    parser.advance();
  }
}

function isAddressLiteral(content: string, policy: AddressLiteral): boolean {
  if (policy === "reject") return false;
  // RFC 5321 §4.1.3: IPv6-comp and IPv6v4-comp compress at least two groups.
  if (policy === "rfc5321" && hasIpv6Tag(content)) {
    const address = content.slice(5);
    if (address.includes("::")) {
      let groups = 0;
      let ipv4 = false;
      for (const group of address.split(":")) {
        if (group !== "") {
          if (group.includes(".")) ipv4 = true;
          else groups++;
        }
      }
      if (groups > (ipv4 ? 4 : 6)) return false;
    }
  }
  if (ipv6AddressLiteral(content) !== undefined) return true;
  if (policy === "rfc5321" && ipv6AddressLiteralWithPaddedTail(content) !== undefined) return true;
  if (hasIpv6Tag(content)) return false;
  if (policy === "routable") return parseIpv4(content) !== undefined;
  return ipv4AddressLiteral(content) !== undefined || isGeneralAddressLiteral(content);
}

/** The case-insensitive `IPv6:` tag (RFC 5234 §2.3). ASCII-only, as Rust's `eq_ignore_ascii_case`. */
function hasIpv6Tag(content: string): boolean {
  if (content.length < 5) return false;
  const tag = content.slice(0, 5).replace(/[A-Z]/g, (c) => c.toLowerCase());
  return tag === "ipv6:";
}

export function ipv6AddressLiteral(content: string): Ipv6 | undefined {
  return hasIpv6Tag(content) ? parseIpv6(content.slice(5)) : undefined;
}

const MAX_IPV6_ADDR_LEN = 64;

export function ipv6AddressLiteralWithPaddedTail(content: string): Ipv6 | undefined {
  if (!hasIpv6Tag(content)) return undefined;
  const addr = content.slice(5);
  const colon = addr.lastIndexOf(":");
  if (colon === -1) return undefined;
  const head = addr.slice(0, colon);
  const tail = addr.slice(colon + 1);
  if (ipv4AddressLiteral(tail) === undefined) return undefined;
  const depadded = tail
    .split(".")
    .map((octet) => octet.replace(/^0+/, "") || "0")
    .join(".");
  const rebuilt = `${head}:${depadded}`;
  // The Rust rewrite goes to a fixed 64-byte stack buffer and gives up past it.
  if (utf8Length(rebuilt) > MAX_IPV6_ADDR_LEN) return undefined;
  return parseIpv6(rebuilt);
}

export function isIpAddressLiteral(content: string): boolean {
  return (
    ipv6AddressLiteral(content) !== undefined ||
    ipv6AddressLiteralWithPaddedTail(content) !== undefined ||
    ipv4AddressLiteral(content) !== undefined
  );
}

/** `IPv4-address-literal`, whose `Snum` admits zero padding. */
export function ipv4AddressLiteral(content: string): Ipv4 | undefined {
  const parts = content.split(".");
  if (parts.length !== 4) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/.test(part)) return undefined;
    const value = Number(part);
    if (value > 255) return undefined;
    octets.push(value);
  }
  return octets as unknown as Ipv4;
}

function isGeneralAddressLiteral(content: string): boolean {
  const colon = content.indexOf(":");
  if (colon === -1) return false;
  const tag = content.slice(0, colon);
  const body = content.slice(colon + 1);
  return /^[A-Za-z0-9-]*[A-Za-z0-9]$/.test(tag) && /^[\x21-\x5a\x5e-\x7e]+$/.test(body);
}

function tryEatFws(parser: Parser): boolean {
  const c = parser.peek();
  if (isWsp(c)) {
    parser.advance();
    while (isWsp(parser.peek())) parser.advance();
    return true;
  }
  if (c === CR) {
    if (parser.unitAt(1) === LF && isWsp(parser.unitAt(2))) {
      parser.pos += 2;
      while (isWsp(parser.peek())) parser.advance();
      return true;
    }
  }
  return false;
}

function skipCfws(parser: Parser, depth: number): void {
  for (;;) {
    for (;;) {
      const c = parser.peek();
      if (isWsp(c)) {
        parser.advance();
      } else if (c === CR && parser.unitAt(1) === LF && isWsp(parser.unitAt(2))) {
        parser.pos += 2;
        while (isWsp(parser.peek())) parser.advance();
      } else {
        break;
      }
    }
    if (parser.peek() === LPAREN) {
      const commentStart = parser.pos;
      try {
        parseComment(parser, depth);
        continue;
      } catch (e) {
        if (!(e instanceof ParseFailure)) throw e;
        // The caller reports a context-appropriate error instead.
        parser.pos = commentStart;
        break;
      }
    }
    break;
  }
}

function parseComment(parser: Parser, depth: number): void {
  if (depth >= MAX_RECURSION_DEPTH || !parser.eat(LPAREN)) parser.fail({ type: "UnterminatedComment" });

  for (;;) {
    const c = parser.peek();
    if (c === RPAREN) {
      parser.advance();
      return;
    }
    if (c === LPAREN) {
      parseComment(parser, depth + 1);
      continue;
    }
    if (c === BACKSLASH) {
      parser.advance();
      if (parser.advance() === END) parser.fail({ type: "UnterminatedComment" });
      continue;
    }
    if (c === END) parser.fail({ type: "UnterminatedComment" });
    if (isCtext(c) || isWsp(c)) {
      parser.advance();
      continue;
    }
    if (c === CR || c === LF) {
      if (!tryEatFws(parser)) parser.fail({ type: "UnterminatedComment" });
      continue;
    }
    // Lenient in comments: obs-ctext controls.
    parser.advance();
  }
}

// ── Character classes (RFC 5322 §3.2.3 + RFC 6531), on code points ──

function isAsciiAlnum(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
}

function isNonAscii(c: number): boolean {
  return c >= 0x80;
}

const ATEXT_SPECIALS = new Set("!#$%&'*+-/=?^_`{|}~".split("").map(ch));

function isAtext(c: number): boolean {
  return isAsciiAlnum(c) || isNonAscii(c) || ATEXT_SPECIALS.has(c);
}

function isPrintableAscii(c: number): boolean {
  return c >= 0x21 && c <= 0x7e;
}

function isObsNoWsCtl(c: number): boolean {
  return (c >= 0x01 && c <= 0x08) || c === 0x0b || c === 0x0c || (c >= 0x0e && c <= 0x1f) || c === 0x7f;
}

function isWsp(c: number): boolean {
  return c === SPACE || c === TAB;
}

function isQtext(c: number, flavor: Quoted): boolean {
  if (c === QUOTE || c === BACKSLASH) return false;
  switch (flavor) {
    case Quoted.Smtp:
      return c === SPACE || isPrintableAscii(c) || isNonAscii(c);
    case Quoted.Header:
      return isPrintableAscii(c) || isNonAscii(c);
    case Quoted.Obsolete:
      return isPrintableAscii(c) || isNonAscii(c) || isObsNoWsCtl(c);
  }
}

function isCtext(c: number): boolean {
  return c !== LPAREN && c !== RPAREN && c !== BACKSLASH && (isPrintableAscii(c) || isNonAscii(c));
}

function isQuotedPairChar(c: number, flavor: Quoted): boolean {
  switch (flavor) {
    case Quoted.Smtp:
      return c === SPACE || isPrintableAscii(c);
    case Quoted.Header:
      return isPrintableAscii(c) || isWsp(c);
    case Quoted.Obsolete:
      return isPrintableAscii(c) || isWsp(c) || c === 0 || c === LF || c === CR || isObsNoWsCtl(c);
  }
}
