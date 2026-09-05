# structured-email-address

RFC 5321/5322/6531 conformant email address parser, validator, and normalizer for Rust.

[![CI](https://github.com/structured-world/structured-email-address/actions/workflows/ci.yml/badge.svg)](https://github.com/structured-world/structured-email-address/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/structured-email-address.svg)](https://crates.io/crates/structured-email-address)
[![docs.rs](https://docs.rs/structured-email-address/badge.svg)](https://docs.rs/structured-email-address)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## What makes this different?

Every Rust email crate stops at RFC validation. This one goes further:

| Feature | `email_address` | `email-address-parser` | **This crate** |
|---------|:-:|:-:|:-:|
| RFC 5322 grammar | Partial | Full | Full |
| RFC 6531 (UTF-8) | Yes | Yes | Yes |
| Subaddress/+tag extraction | - | - | **Yes** |
| Provider-aware dot-stripping | - | - | **Yes** |
| Configurable case folding | - | - | **Yes** |
| PSL domain validation | - | - | **Yes** |
| Anti-homoglyph detection | - | - | **Yes** |
| IDN domain Unicode accessor | - | - | **Yes** |
| Global vs local domain scope | - | - | **Yes** |
| Display name parsing | Yes | - | **Yes** |
| Configurable strictness | Partial | Partial | **Full** |
| Serde support | Yes | - | **Yes** |
| Zero dependencies* | Yes | nom | `idna` + 3 |

\* Dependencies: `idna`, `unicode-normalization`, `unicode-security`. Optional: `structured-public-domains`, `serde`.

## Quick Start

```rust
use structured_email_address::{EmailAddress, Config};

// Parse with defaults (RFC 5322 Standard mode)
let email: EmailAddress = "user+tag@example.com".parse()?;
assert_eq!(email.local_part(), "user+tag");
assert_eq!(email.tag(), Some("tag"));
assert_eq!(email.domain(), "example.com");

// International domains: IDNA roundtrip
let email: EmailAddress = "user@münchen.de".parse()?;
assert_eq!(email.domain(), "xn--mnchen-3ya.de");
assert_eq!(email.domain_unicode(), "münchen.de");
```

## Configured Parsing

```rust
use structured_email_address::{EmailAddress, Config};

let config = Config::builder()
    .strip_subaddress()          // user+tag → user
    .dots_gmail_only()           // a.l.i.c.e@gmail.com → alice@gmail.com
    .lowercase_all()             // USER → user
    .check_confusables()         // detect Cyrillic lookalikes
    .domain_check_psl()          // verify domain in Public Suffix List
    .build();

let email = EmailAddress::parse_with("A.L.I.C.E+promo@Gmail.COM", &config)?;
assert_eq!(email.canonical(), "alice@gmail.com");
assert_eq!(email.tag(), Some("promo"));
assert!(email.is_freemail());
```

## Provider-Aware Normalization

Each known provider carries its own rule (dot handling, case folding, subaddress
separator, freemail flag). Enable `provider_aware()` to normalize a matched
address by its provider's rule instead of the global policies, and register your
own providers:

```rust
use structured_email_address::{Config, EmailAddress, ProviderRule};

let config = Config::builder()
    .provider_aware()            // matched provider's rule governs the address
    .strip_subaddress()
    .add_provider(               // extend the built-in registry
        ProviderRule::new(["mail.corp.example"])
            .strip_dots(true)
            .lowercase_local(true)
            .subaddress_separator(Some('-')),
    )
    .build();

// Gmail's built-in rule strips dots + folds case even with no global policy set:
let g = EmailAddress::parse_with("A.Li.Ce+promo@Gmail.com", &config)?;
assert_eq!(g.canonical(), "alice@gmail.com");

// Custom provider with a '-' separator:
let c = EmailAddress::parse_with("John.Doe-tag@mail.corp.example", &config)?;
assert_eq!(c.local_part(), "johndoe");
assert_eq!(c.tag(), Some("tag"));
```

Built-in providers: Gmail/Googlemail (dot-stripping), Outlook, Yahoo, ProtonMail,
iCloud, Yandex, Mail.ru, and other common freemail domains. `is_freemail()`
consults the same registry regardless of `provider_aware`.

## Display Names

```rust
use structured_email_address::{EmailAddress, Config};

let config = Config::builder().allow_display_name().build();
let email = EmailAddress::parse_with("John Doe <user@example.com>", &config)?;
assert_eq!(email.display_name(), Some("John Doe"));
```

## Batch Parsing

Parse thousands of addresses in one call. Config is shared, results preserve input order:

```rust
use structured_email_address::{EmailAddress, Config};

let config = Config::builder().strip_subaddress().lowercase_all().build();
let results = EmailAddress::parse_batch(
    &["alice@example.com", "invalid", "bob+tag@example.org"],
    &config,
);
assert!(results[0].is_ok());
assert!(results[1].is_err());
assert!(results[2].is_ok());
```

For large lists (10K+), enable the `rayon` feature for parallel parsing:

```toml
structured-email-address = { version = "0.0.1", features = ["rayon"] }
```

```rust,ignore
let results = EmailAddress::parse_batch_par(&huge_list, &config);
```

### Batch Benchmarks (baseline)

100K emails (mix of valid + invalid), `strip_subaddress` + `dots_gmail_only` + `lowercase_all` config.
Apple M1 Pro, Rust 1.85, `cargo bench --all-features`.

| Variant | Time | Throughput |
|---------|------|-----------|
| `parse_batch` (sequential) | 49.1 ms | ~2.0M emails/sec |
| `parse_batch_par` (rayon) | 9.6 ms | ~10.4M emails/sec |

Rayon gives ~5x speedup on this workload.

## Strictness Levels

| Level | Grammar | Use case |
|-------|---------|----------|
| `Strict` | RFC 5321 (envelope) | SMTP validation, reject exotic addresses |
| `Standard` | RFC 5322 (header) | Default — full grammar, no obsolete forms |
| `Lax` | RFC 5322 + obs-* | Legacy system interop |

`Strict` refuses a quoted local part, because an address like `"a b"@example.com`
is valid and unroutable in practice. A consumer reading an identity rather than
routing to it needs the alternative back, and asks for it:

```rust
use structured_email_address::{Config, EmailAddress, Strictness};

// RFC 5321 §4.1.2 Mailbox as written: Dot-string or Quoted-string, no comments.
let mailbox = Config::builder()
    .strictness(Strictness::Strict)
    .allow_quoted_local_part()
    .build();

let email = EmailAddress::parse_with("\"a b\"@example.com", &mailbox).unwrap();
assert_eq!(email.local_part(), "a b");
assert_eq!(email.canonical(), "\"a b\"@example.com");

// The alphabet is the envelope one, so header syntax stays out.
assert!(EmailAddress::parse_with("a(comment)@example.com", &mailbox).is_err());
```

## Domain Scope

A parse says whether the text is an address the configured grammar names. It
does not say whether the domain reaches anywhere: `admin@printer`,
`postmaster@files.local` and `a@[192.168.1.5]` are as well formed as
`a@example.com`, and what separates them is reach, not syntax.

```rust
use structured_email_address::{Config, DomainScope, EmailAddress, IpScope, LiteralScope};

let config = Config::builder()
    .allow_single_label_domain()
    .allow_address_literal_rfc5321()
    .build();
let scope = |input| EmailAddress::parse_with(input, &config).unwrap().domain_scope();

assert_eq!(scope("a@example.com"), DomainScope::Global);
assert_eq!(scope("admin@printer"), DomainScope::Local);
assert_eq!(scope("a@files.local"), DomainScope::Local);
assert_eq!(
    scope("a@[192.168.1.5]"),
    DomainScope::Literal(LiteralScope::Ipv4(IpScope::Local)),
);
assert!(scope("a@[192.0.2.1]").is_global());
```

`Local` covers a single label and the names reserved by RFC 6761 (`.test`,
`.example`, `.invalid`, `.localhost`), RFC 6762 (`.local`), RFC 8375
(`home.arpa`), ICANN (`.internal`), and the two the DNS never resolves at all,
RFC 7686 (`.onion`) and RFC 9476 (`.alt`) — matched on whole labels, so
`notlocal.com` is `Global`. A literal reports its family and whether the address
is one that stays inside a network: RFC 1918 and RFC 6598 for v4, `fc00::/7` for
v6, the link-local and site-local ranges, loopback, the limited broadcast
address, the benchmarking block, and multicast below global scope. An address
that embeds an IPv4 one reports the reach of the address it holds.

Nothing here changes a verdict. A single-label domain stays refused unless
`allow_single_label_domain` asks for it; the classification is for the consumer
that has opted in and now has to tell the two apart. With the `psl` feature off,
`Global` weakens from "under a published public suffix" to "the final label is
TLD-like", so a `no_std` consumer gets an answer rather than a compile error.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Operating-system integration in dependencies. Turn it off for `no_std` |
| `alloc` | Yes (via `std`) | Names the `core` + `alloc` build. An allocator is required either way |
| `serde` | Yes | Serialize/deserialize as canonical string |
| `psl` | Yes | Domain validation against Public Suffix List. Implies `std` until `structured-public-domains` ships its own no-std build |
| `rayon` | No | Parallel batch parsing via `parse_batch_par()` (implies `std`) |

```toml
# Minimal (no serde, no PSL)
structured-email-address = { version = "0.0.17", default-features = false }
```

### `no_std`

The parser and validator build against `core` + `alloc`, so they run in a WASM
sandbox or on bare metal. Nothing here needs a pointer-width atomic either, so
the crate builds on targets without compare-and-swap. CI checks both
`thumbv7em-none-eabihf` and `thumbv6m-none-eabi`, because a host check cannot
fail on a constraint the host does not have: `std` is present there, so code
reaching for it still compiles, and the host has the atomics `thumbv6m` lacks.

```toml
structured-email-address = { version = "0.0.17", default-features = false, features = ["alloc"] }
```

An allocator is not optional: every parse produces owned strings. The `psl`
feature declares `std` as a requirement, since `structured-public-domains` has
not made the same move yet; a no-std build therefore leaves PSL validation out
and keeps the rest.

## Anti-Homoglyph Protection

Detects visually confusable email addresses using Unicode skeleton mapping:

```rust
use structured_email_address::confusable_skeleton;

// Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
assert_eq!(
    confusable_skeleton("аlice"),  // Cyrillic а
    confusable_skeleton("alice"),  // Latin a
);
```

## Conformance

Validated against the [isEmail](https://github.com/dominicsayers/isemail) test
suite (v3.05, 164 edge cases), the same corpus used by `email-address-parser`.
All 164 cases pass: valid addresses (RFC 5321/5322 quoted strings, IPv4/IPv6
address literals, comments, folding whitespace, obsolete forms) are accepted at
the appropriate strictness level, while malformed inputs (bad IP literals,
over-length parts, bare control characters) are rejected. See
[`tests/conformance.rs`](tests/conformance.rs).

## Support the Project

<div align="center">

![USDT TRC-20 Donation QR Code](assets/usdt-qr.svg)

USDT (TRC-20), maintainer's personal wallet: `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`

</div>

## License

Copyright 2026 Dmitry Prudnikov. Apache License 2.0; see [LICENSE](LICENSE).
