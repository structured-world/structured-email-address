// Domain scope: a port of the Rust crate's `src/scope.rs`, where each reserved
// name and range is listed with the document reserving it.

import { isKnownSuffix } from "@structured-world/structured-public-domains/tiny";

import type { DomainScope, IpScope, LiteralScope } from "../../shared/src/types.js";
import { embeddedIpv4, isIpv6Loopback, isIpv6Unspecified, type Ipv4, type Ipv6 } from "./net.js";
import { ipv4AddressLiteral, ipv6AddressLiteral, ipv6AddressLiteralWithPaddedTail } from "./parser.js";

const RESERVED = ["localhost", "test", "invalid", "example", "local", "home.arpa", "internal", "onion", "alt"];

/** Whether `domain` is `name` or under it, on whole labels. */
function isWithin(domain: string, name: string): boolean {
  if (!domain.endsWith(name)) return false;
  const prefix = domain.slice(0, domain.length - name.length);
  return prefix === "" || prefix.endsWith(".");
}

export function classify(domain: string): DomainScope {
  if (domain.startsWith("[") && domain.endsWith("]")) {
    return { kind: "literal", literal: literalScope(domain.slice(1, -1)) };
  }
  if (!domain.includes(".") || RESERVED.some((name) => isWithin(domain, name)) || !isKnownSuffix(domain)) {
    return { kind: "local" };
  }
  return { kind: "global" };
}

function literalScope(content: string): LiteralScope {
  const v6 = ipv6AddressLiteral(content) ?? ipv6AddressLiteralWithPaddedTail(content);
  if (v6 !== undefined) return { kind: "ipv6", ip: ipv6Scope(v6) };
  const v4 = ipv4AddressLiteral(content);
  if (v4 !== undefined) return { kind: "ipv4", ip: ipv4Scope(v4) };
  return { kind: "general" };
}

function ipv4Scope([a, b, c, d]: Ipv4): IpScope {
  const local =
    a === 10 ||
    (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    a === 127 ||
    a === 0 ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 255 && b === 255 && c === 255 && d === 255) ||
    (a === 224 && b === 0 && c === 0) ||
    a === 239;
  return local ? "local" : "global";
}

function ipv6Scope(addr: Ipv6): IpScope {
  if (isIpv6Loopback(addr) || isIpv6Unspecified(addr)) return "local";
  const embedded = embeddedIpv4(addr);
  if (embedded !== undefined) return ipv4Scope(embedded);
  const leading = addr[0];
  const boundedMulticast = (leading & 0xff00) === 0xff00 && (leading & 0x000f) !== 0x000e;
  const local =
    (leading & 0xfe00) === 0xfc00 ||
    (leading & 0xffc0) === 0xfe80 ||
    (leading & 0xffc0) === 0xfec0 ||
    boundedMulticast;
  return local ? "local" : "global";
}
