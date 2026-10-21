// UTS #39 confusable skeleton, as the Rust crate computes it: NFC, then the
// skeleton (NFD, prototype per character, NFD), then lowercase.

import { CONFUSABLES } from "../generated/confusables-data.js";

let table: Map<number, string> | undefined;

/** Decode the generated table on first use; most configurations never ask. */
function prototypes(): Map<number, string> {
  if (table !== undefined) return table;
  table = new Map();
  for (const entry of CONFUSABLES.split(",")) {
    const colon = entry.indexOf(":");
    const source = parseInt(entry.slice(0, colon), 16);
    const target = entry
      .slice(colon + 1)
      .split(" ")
      .map((hex) => String.fromCodePoint(parseInt(hex, 16)))
      .join("");
    table.set(source, target);
  }
  return table;
}

/** Compute the confusable skeleton; two strings with the same one look alike. */
export function confusableSkeleton(input: string): string {
  const map = prototypes();
  let mapped = "";
  for (const ch of input.normalize("NFC").normalize("NFD")) {
    mapped += map.get(ch.codePointAt(0)!) ?? ch;
  }
  return mapped.normalize("NFD").toLowerCase();
}
