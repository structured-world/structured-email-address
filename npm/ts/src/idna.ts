// UTS #46 through tr46, the jsdom implementation, configured as the Rust `idna`
// 1.x calls the crate makes. `idna` always sets CheckBidi and CheckJoiners and
// never Transitional_Processing; its documentation maps the remaining flags:
//
//   domain_to_ascii_strict: UseSTD3ASCIIRules, CheckHyphens, VerifyDnsLength
//   domain_to_ascii:        none of them
//   domain_to_unicode:      none of them

import tr46 from "tr46";

const ALWAYS = { checkBidi: true, checkJoiners: true, transitionalProcessing: false } as const;

/** `idna::domain_to_ascii_strict`, or `undefined` on any UTS #46 error. */
export function toAsciiStrict(domain: string): string | undefined {
  return (
    tr46.toASCII(domain, { ...ALWAYS, useSTD3ASCIIRules: true, checkHyphens: true, verifyDNSLength: true }) ??
    undefined
  );
}

/** `idna::domain_to_ascii`, or `undefined` on any UTS #46 error. */
export function toAscii(domain: string): string | undefined {
  return tr46.toASCII(domain, ALWAYS) ?? undefined;
}

/** `idna::domain_to_unicode`: the Unicode form, and whether processing found errors. */
export function toUnicode(domain: string): { domain: string; error: boolean } {
  return tr46.toUnicode(domain, ALWAYS);
}
