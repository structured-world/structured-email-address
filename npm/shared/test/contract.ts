// The API contract both backends must honour, beyond the results the parity
// corpus compares: initialization, the error type, option validation and the
// JavaScript-only cases Rust never sees. Each backend's test file runs it.
import { describe, expect, it } from "vitest";

import type { Config, EmailAddress, ParseOutcome, Parser } from "../src/public.js";
import { EmailAddressError } from "../src/public.js";

/** The functions every backend package exports. */
export interface Backend {
  init(): Promise<void>;
  isInitialized(): boolean;
  createParser(config?: Config): Parser;
  parse(input: string, config?: Config): EmailAddress;
  parseBatch(inputs: readonly string[], config?: Config): ParseOutcome[];
  isSmtpMailbox(input: string): boolean;
  confusableSkeleton(input: string): string;
}

export function contract(name: string, backend: Backend): void {
  describe(`${name}: before init`, () => {
    it("refuses to parse, so a missing init fails loudly instead of answering wrongly", () => {
      expect(backend.isInitialized()).toBe(false);
      expect(() => backend.parse("a@example.com")).toThrow(/init/);
    });
  });

  describe(`${name}: after init`, () => {
    it("initializes once and stays initialized", async () => {
      await backend.init();
      await backend.init();
      expect(backend.isInitialized()).toBe(true);
    });

    it("parses with the Rust crate's defaults", () => {
      const email = backend.parse("user+tag@Example.COM");
      expect(email.localPart).toBe("user+tag");
      expect(email.tag).toBe("tag");
      expect(email.domain).toBe("example.com");
      expect(email.canonical).toBe("user+tag@example.com");
      expect(email.domainScope).toEqual({ kind: "global" });
      // Absent fields are absent, not undefined-valued, so objects compare cleanly.
      expect("displayName" in email).toBe(false);
    });

    it("runs the Gmail normalization pipeline", () => {
      const email = backend.parse("A.L.I.C.E+promo@Gmail.COM", {
        subaddress: "strip",
        dotPolicy: "gmailOnly",
        casePolicy: "all",
      });
      expect(email.canonical).toBe("alice@gmail.com");
      expect(email.freemail).toBe(true);
    });

    it("throws EmailAddressError with the Rust message, kind and position", () => {
      try {
        backend.parse("user@");
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(EmailAddressError);
        const err = e as EmailAddressError;
        expect(err.kind).toEqual({ type: "EmptyDomain" });
        expect(err.position).toBe(5);
        expect(err.message).toBe("empty domain");
      }
    });

    it("reports positions in UTF-16 units, which index the input string", () => {
      // Two astral characters: four UTF-16 units, eight UTF-8 bytes.
      const input = "😀😀@";
      try {
        backend.parse(input);
        expect.unreachable();
      } catch (e) {
        expect((e as EmailAddressError).position).toBe(5);
        expect(input.slice(0, 4)).toBe("😀😀");
      }
    });

    it("counts length limits in octets, as RFC 5321 does", () => {
      // 33 two-byte letters: 66 octets, over the 64-octet local-part limit.
      const local = String.fromCodePoint(0x436).repeat(33);
      expect(() => backend.parse(`${local}@example.com`)).toThrow(
        expect.objectContaining({ kind: { type: "LocalPartTooLong", len: 66 } }),
      );
    });

    it("refuses an unpaired surrogate at its offset instead of reading it as U+FFFD", () => {
      const input = `a${String.fromCharCode(0xd800)}b@example.com`;
      expect(() => backend.parse(input)).toThrow(
        expect.objectContaining({ kind: { type: "Unexpected", ch: String.fromCharCode(0xd800) }, position: 1 }),
      );
    });

    it("parses a batch in order, with one outcome per input", () => {
      const results = backend.parseBatch(["a@example.com", "bad", `x${String.fromCharCode(0xdc00)}@y.com`, "b@example.org"]);
      expect(results.map((r) => r.ok)).toEqual([true, false, false, true]);
      const failed = results[1]!;
      expect(!failed.ok && failed.error).toBeInstanceOf(EmailAddressError);
    });

    it("binds a configuration once with createParser", () => {
      const parser = backend.createParser({ allowDisplayName: true });
      const email = parser.parse('"Doe, John" <john@example.com>');
      expect(email.displayName).toBe("Doe, John");
      expect(email.formatted).toBe('"Doe, John" <john@example.com>');
    });

    it("validates options rather than ignoring a misspelled value", () => {
      expect(() => backend.parse("a@b.com", { strictness: "loose" as never })).toThrow(TypeError);
      expect(() => backend.parse("a@b.com", { subaddressSeparator: "++" })).toThrow(TypeError);
    });

    it("applies custom providers on top of the built-ins", () => {
      const email = backend.parse("Some.One+x@Mail.Example.com", {
        providerAware: true,
        providers: [{ domains: ["mail.example.com"], stripDots: true, lowercaseLocal: true, freemail: true }],
      });
      expect(email.localPart).toBe("someone+x");
      expect(email.freemail).toBe(true);
    });

    it("validates against the Public Suffix List", () => {
      expect(backend.parse("a@example.co.uk", { domainCheck: "psl" }).domain).toBe("example.co.uk");
      expect(() => backend.parse("a@example.invalidtld", { domainCheck: "psl" })).toThrow(
        expect.objectContaining({ kind: { type: "UnknownTld", tld: "invalidtld" } }),
      );
    });

    it("classifies domain scope", () => {
      const config: Config = { allowSingleLabelDomain: true, addressLiteral: "rfc5321" };
      expect(backend.parse("admin@printer", config).domainScope).toEqual({ kind: "local" });
      expect(backend.parse("a@[192.168.1.5]", config).domainScope).toEqual({
        kind: "literal",
        literal: { kind: "ipv4", ip: "local" },
      });
    });

    it("checks SMTP mailbox syntax", () => {
      expect(backend.isSmtpMailbox('"a b"@localhost')).toBe(true);
      expect(backend.isSmtpMailbox("Alice <user@example.com>")).toBe(false);
    });

    it("computes confusable skeletons", () => {
      // Cyrillic а (U+0430) in place of Latin a.
      expect(backend.confusableSkeleton(`p${String.fromCodePoint(0x430)}ypal`)).toBe("paypal");
    });
  });
}
