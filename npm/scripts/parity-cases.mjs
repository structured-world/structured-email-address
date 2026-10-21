// Print the parity corpus, one JSON case per line, for the Rust harness
// (bindings/wasm/examples/parity.rs) and both npm backends (scripts/parity.mjs)
// to answer. Inputs are the isEmail suite plus cases aimed at the places the
// two implementations could drift: Unicode handling, IDNA, IP parsing,
// provider rules, scope and length limits. Every input runs under every
// configuration below, and every scalar value goes through the skeleton.
// Run: node scripts/parity-cases.mjs > cases.jsonl
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // npm/scripts
const suite = readFileSync(join(here, "..", "..", "tests", "isemail_tests.xml"), "utf8");

/** Invisible and control characters are spelled by code point, never literally. */
const c = (...cps) => String.fromCodePoint(...cps);

/** The Rust crate's `Config::default`, spelled as a resolved config. */
const DEFAULTS = {
  strictness: "standard",
  dotPolicy: "preserve",
  casePolicy: "domain",
  domainCheck: "syntax",
  subaddress: "preserve",
  subaddressSeparator: "+",
  checkConfusables: false,
  addressLiteral: "reject",
  allowDisplayName: false,
  allowSingleLabelDomain: false,
  allowQuotedLocalPart: false,
  providerAware: false,
  builtinProviders: true,
  providers: [],
};

const provider = (domains, rest = {}) => ({
  domains,
  stripDots: false,
  lowercaseLocal: false,
  subaddressSeparator: "+",
  freemail: false,
  ...rest,
});

const CONFIGS = [
  {},
  { strictness: "strict", allowQuotedLocalPart: true, addressLiteral: "rfc5321", allowSingleLabelDomain: true },
  { strictness: "strict" },
  { strictness: "lax", addressLiteral: "routable", allowSingleLabelDomain: true },
  { subaddress: "strip", dotPolicy: "gmailOnly", casePolicy: "all", checkConfusables: true, domainCheck: "psl" },
  {
    providerAware: true,
    providers: [
      provider(["münchen.de"], { subaddressSeparator: "-", lowercaseLocal: true, freemail: true }),
      provider(["NoTags.Example"], { subaddressSeparator: null, stripDots: true }),
      provider(["gmail.com"], { stripDots: false, lowercaseLocal: false }),
    ],
  },
  {
    allowDisplayName: true,
    domainCheck: "tld",
    casePolicy: "preserve",
    subaddressSeparator: "-",
    addressLiteral: "rfc5321",
  },
  { strictness: "lax", allowDisplayName: true, dotPolicy: "always", domainCheck: "psl", checkConfusables: true },
  {
    providerAware: true,
    builtinProviders: false,
    dotPolicy: "gmailOnly",
    providers: [provider(["Example.COM"], { stripDots: true, freemail: true })],
  },
].map((overrides) => ({ ...DEFAULTS, ...overrides }));

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/** The suite writes control characters as their Control Pictures, U+2400 to U+2421. */
function decodeControls(text) {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x2400 && cp <= 0x241f) out += c(cp - 0x2400);
    else if (cp === 0x2420) out += " ";
    else if (cp === 0x2421) out += c(0x7f);
    else out += ch;
  }
  return out;
}

/** XML text decoding, then the control pictures back to controls. */
function decode(text) {
  const xml = text.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-z]+);/g, (m, e) =>
    e[0] === "#" ? c(e[1] === "x" ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : (ENTITIES[e] ?? m),
  );
  return decodeControls(xml);
}

const isemail = [...suite.matchAll(/<address>([\s\S]*?)<\/address>|<address\/>/g)].map((m) => decode(m[1] ?? ""));

const CR = c(0x0d);
const LF = c(0x0a);
const TAB = c(0x09);
const NUL = c(0x00);
const CYRILLIC_ZHE = c(0x0436);
const EXTRA = [
  // Plain, tags, providers.
  "user@example.com",
  "user+tag@example.com",
  "+tag@example.com",
  "user+@example.com",
  "a+b+c@example.com",
  "A.L.I.C.E+promo@Gmail.COM",
  "Foo.Bar+x@GoogleMail.com",
  "First.Last@Hotmail.com",
  "x.y-z@münchen.de",
  "X.Y-Z@xn--mnchen-3ya.de",
  "a.b+c@notags.example",
  "a.b+c@example.com",
  // Unicode local parts and domains.
  "пользователь@example.com",
  "用户@例子.广告",
  "😀@example.com",
  "😀😀@",
  "😀 @b.com",
  `u${c(0x308)}ser@example.com`,
  `user@mu${c(0x308)}nchen.de`,
  "user@MÜNCHEN.DE",
  "user@bücher.example",
  "user@例え.jp",
  "user@مثال.إختبار",
  `user@a${c(0x200d)}b.com`,
  `user@a${c(0x200c)}b.com`,
  "user@ab--cd.com",
  "user@xn--a.com",
  "user@xn--.com",
  "user@ß.de",
  "user@faß.de",
  "user@𝐚𝐛.com",
  "user@b_c.com",
  "İSTANBUL@example.com",
  "ΟΔΟΣ@example.com",
  `p${c(0x430)}ypal@example.com`,
  "ｆｕｌｌｗｉｄｔｈ@example.com",
  `${c(0x2126)}mega@example.com`,
  `a${c(0xad)}b@example.com`,
  `user@a${c(0xad)}b.com`,
  // Quoted local parts.
  '"a b"@example.com',
  '"a\\"b"@example.com',
  '"a\\\\b"@example.com',
  '""@example.com',
  '"a..b"@example.com',
  '"."@example.com',
  '"a+b.c"@gmail.com',
  `"a${CR}${LF} b"@example.com`,
  `"a${TAB}b"@example.com`,
  '"é"@example.com',
  '"a"."b"@example.com',
  // Display names.
  '"Doe, John" <john@example.com>',
  "John Doe <john@example.com>",
  `John Doe${c(0xa0)} <john@example.com>`,
  `Name${c(0xfeff)} <a@b.com>`,
  `Name${c(0x85)}<a@b.com>`,
  `Name${c(0x2028)}<a@b.com>`,
  '"Esc\\"aped \\\\ name" <a@b.com>',
  `"Fold${CR}${LF} ed" <a@b.com>`,
  "<a@b.com>",
  "Name <a@b.com",
  "Name a@b.com>",
  ' "Lead" <a@b.com> ',
  // Comments and whitespace.
  "a(comment)@b.com",
  "(c)a@b.com",
  "a@(c)b.com",
  "a@b.com(c)",
  "a@b.com((nested)(c))",
  "a@b.com(unterminated",
  " a@b.com ",
  "a @b.com",
  "a@ b.com",
  "a . b@c.com",
  "a@b . com",
  `a@b.com${CR}${LF} `,
  `user@host${LF}`,
  `user@host${CR}`,
  // Address literals.
  "a@[192.168.1.5]",
  "a@[012.0.2.1]",
  "a@[256.0.0.1]",
  "a@[1.2.3]",
  "a@[1.2.3.4.5]",
  "a@[IPv6:::1]",
  "a@[ipv6:2001:DB8::1]",
  "a@[IPV6:2001:db8::1]",
  "a@[IPv6:::ffff:192.168.1.5]",
  "a@[IPv6:::ffff:012.0.2.1]",
  "a@[IPv6:::192.168.1.5]",
  "a@[IPv6:1:2:3:4:5:6:7::]",
  "a@[IPv6:1::2:3:4:5:6:7]",
  "a@[IPv6:1:2:3:4:5:6:7:8]",
  "a@[IPv6:1:2:3:4:5:6:1.2.3.4]",
  "a@[IPv6:1:2:3:4:5:6:7:1.2.3.4]",
  "a@[IPv6:12345::]",
  "a@[IPv6:fe80::1]",
  "a@[IPv6:ff02::1]",
  "a@[IPv6:ff0e::1]",
  "a@[IPv6:fc00::1]",
  "a@[IPv6:fec0::1]",
  "a@[IPv6:::]",
  "a@[IPv6:2001:db8::1]",
  "a@[IPv6:zzz]",
  "a@[AS400:QSYS]",
  "a@[as400:qsys]",
  "a@[-tag:x]",
  "a@[tag-:x]",
  "a@[tag:]",
  "a@[tag:a b]",
  "a@[a\\]b]",
  "a@[255.255.255.255]",
  "a@[224.0.0.1]",
  "a@[224.0.1.1]",
  "a@[239.1.1.1]",
  "a@[100.64.0.1]",
  "a@[198.18.0.1]",
  "a@[0.0.0.0]",
  "a@[192.0.2.1]",
  "a@[1.2.3.4",
  // Scope.
  "admin@printer",
  "a@files.local",
  "a@x.home.arpa",
  "a@nothome.arpa",
  "a@x.onion",
  "a@a.alt",
  "a@a.internal",
  "a@example.invalid",
  "a@x.test",
  "a@localhost",
  "a@a.github.io",
  "a@a.unknowntld",
  "a@a.co.uk",
  "a@a.xn--p1ai",
  "a@a.рф",
  "a@a.c0m",
  "a@a.x",
  // Lengths.
  `${"a".repeat(64)}@example.com`,
  `${"a".repeat(65)}@example.com`,
  `${CYRILLIC_ZHE.repeat(32)}@example.com`,
  `${CYRILLIC_ZHE.repeat(33)}@example.com`,
  `a@${"b".repeat(63)}.com`,
  `a@${"b".repeat(64)}.com`,
  `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(57)}.com`,
  `${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(58)}.com`,
  `a@${"ü".repeat(60)}.com`,
  // Syntax errors.
  "",
  " ",
  "@",
  "a@",
  "@b.com",
  "a",
  "a@b",
  "a@-b.com",
  "a@b-.com",
  "a..b@c.com",
  ".a@b.com",
  "a.@b.com",
  "a@b..com",
  "a@b.com.",
  "a@.b.com",
  "a b@c.com",
  "a@b.com>",
  'a"b@c.com',
  "a\\b@c.com",
  "a@b@c.com",
  "a@b,c.com",
  `a@${NUL}.com`,
  `${NUL}@b.com`,
];

const inputs = [...new Set([...isemail, ...EXTRA])];

const lines = [];
for (const config of CONFIGS) {
  for (const input of inputs) lines.push(JSON.stringify({ op: "parse", config, input }));
}
for (const input of inputs) {
  lines.push(JSON.stringify({ op: "smtp", input }));
  lines.push(JSON.stringify({ op: "skeleton", input }));
}
for (let cp = 0; cp <= 0x10ffff; cp++) {
  if (cp >= 0xd800 && cp <= 0xdfff) continue;
  lines.push(JSON.stringify({ op: "skeleton", input: c(cp) }));
}

// JSON leaves U+2028 and U+2029 unescaped, and readline splits lines on them.
const LINE_SEPARATORS = new RegExp(`[${c(0x2028)}${c(0x2029)}]`, "g");
const escaped = lines.join(LF).replace(LINE_SEPARATORS, (s) => `\\u${s.charCodeAt(0).toString(16)}`);
process.stdout.write(escaped + LF);
