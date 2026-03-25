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
| Display name parsing | Yes | - | **Yes** |
| Configurable strictness | Partial | Partial | **Full** |
| Serde support | Yes | - | **Yes** |
| Zero dependencies* | Yes | nom | `idna` + 3 |

\* Dependencies: `idna`, `unicode-normalization`, `unicode-security`. Optional: `psl`, `serde`.

## Quick Start

```rust
use structured_email_address::{EmailAddress, Config};

// Parse with defaults (RFC 5322 Standard mode)
let email: EmailAddress = "user+tag@example.com".parse()?;
assert_eq!(email.local_part(), "user+tag");
assert_eq!(email.tag(), Some("tag"));
assert_eq!(email.domain(), "example.com");
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

## Display Names

```rust
use structured_email_address::{EmailAddress, Config};

let config = Config::builder().allow_display_name().build();
let email = EmailAddress::parse_with("John Doe <user@example.com>", &config)?;
assert_eq!(email.display_name(), Some("John Doe"));
```

## Strictness Levels

| Level | Grammar | Use case |
|-------|---------|----------|
| `Strict` | RFC 5321 (envelope) | SMTP validation, reject exotic addresses |
| `Standard` | RFC 5322 (header) | Default — full grammar, no obsolete forms |
| `Lax` | RFC 5322 + obs-* | Legacy system interop |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `serde` | Yes | Serialize/deserialize as canonical string |
| `psl` | Yes | Domain validation against Public Suffix List |

```toml
# Minimal (no serde, no PSL)
structured-email-address = { version = "0.1", default-features = false }
```

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

## Support the Project

<div align="center">

![USDT TRC-20 Donation QR Code](assets/usdt-qr.svg)

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`

</div>

## License

Apache License 2.0
