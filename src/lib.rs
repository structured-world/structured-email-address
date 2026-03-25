//! # structured-email-address
//!
//! RFC 5321/5322/6531 conformant email address parser, validator, and normalizer.
//!
//! Unlike existing Rust crates that stop at RFC validation, this crate provides:
//! - **Subaddress extraction**: `user+tag@domain` → separate `user`, `tag`, `domain`
//! - **Provider-aware normalization**: Gmail dot-stripping, configurable case folding
//! - **PSL domain validation**: verify domain against the Public Suffix List
//! - **Anti-homoglyph protection**: detect Cyrillic/Latin lookalikes via Unicode skeleton
//! - **Configurable strictness**: Strict (5321), Standard (5322), Lax (obs-* allowed)
//! - **Zero-copy parsing**: internal spans into the input string
//!
//! # Quick Start
//!
//! ```
//! use structured_email_address::{EmailAddress, Config};
//!
//! // Simple: parse with defaults
//! let email: EmailAddress = "user+tag@example.com".parse().unwrap();
//! assert_eq!(email.local_part(), "user+tag");
//! assert_eq!(email.tag(), Some("tag"));
//! assert_eq!(email.domain(), "example.com");
//!
//! // Configured: Gmail normalization pipeline
//! let config = Config::builder()
//!     .strip_subaddress()
//!     .dots_gmail_only()
//!     .lowercase_all()
//!     .build();
//!
//! let email = EmailAddress::parse_with("A.L.I.C.E+promo@Gmail.COM", &config).unwrap();
//! assert_eq!(email.canonical(), "alice@gmail.com");
//! assert_eq!(email.tag(), Some("promo"));
//! ```

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod config;
mod error;
mod normalize;
mod parser;
mod validate;

pub use config::{
    CasePolicy, Config, ConfigBuilder, DomainCheck, DotPolicy, Strictness, SubaddressPolicy,
};
pub use error::{Error, ErrorKind};
pub use normalize::confusable_skeleton;

/// A parsed, validated, and normalized email address.
///
/// Immutable after construction. All accessors return borrowed data.
#[derive(Debug, Clone)]
pub struct EmailAddress {
    /// Original input (trimmed).
    original: String,
    /// Canonical local part (after normalization).
    local_part: String,
    /// Extracted subaddress tag, if any.
    tag: Option<String>,
    /// Canonical domain (IDNA-encoded, lowercased).
    domain: String,
    /// Display name, if parsed from `name-addr` format.
    display_name: Option<String>,
    /// Confusable skeleton, if config enabled it.
    skeleton: Option<String>,
}

impl EmailAddress {
    /// Parse and validate with the given configuration.
    pub fn parse_with(input: &str, config: &Config) -> Result<Self, Error> {
        let parsed = parser::parse(
            input,
            config.strictness,
            config.allow_display_name,
            config.allow_domain_literal,
        )?;

        let normalized = normalize::normalize(&parsed, config);
        validate::validate(&parsed, &normalized, config)?;

        Ok(Self {
            original: parsed.input.to_string(),
            local_part: normalized.local_part,
            tag: normalized.tag,
            domain: normalized.domain,
            display_name: normalized.display_name,
            skeleton: normalized.skeleton,
        })
    }

    /// The canonical local part (after normalization).
    ///
    /// If subaddress stripping is enabled, this excludes the `+tag`.
    /// If dot stripping is enabled, dots are removed.
    pub fn local_part(&self) -> &str {
        &self.local_part
    }

    /// The extracted subaddress tag, if present.
    ///
    /// For `user+promo@example.com`, returns `Some("promo")`.
    /// Always extracted regardless of [`SubaddressPolicy`] — the policy only
    /// affects whether it appears in [`canonical()`](Self::canonical).
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The canonical domain (IDNA-encoded, lowercased).
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The display name, if parsed from `"Name" <addr>` or `Name <addr>` format.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// The full canonical address: `local_part@domain`.
    pub fn canonical(&self) -> String {
        format!("{}@{}", self.local_part, self.domain)
    }

    /// The original input (trimmed).
    pub fn original(&self) -> &str {
        &self.original
    }

    /// The confusable skeleton of the local part (if config enabled it).
    ///
    /// Two addresses with the same skeleton + domain are visually confusable.
    pub fn skeleton(&self) -> Option<&str> {
        self.skeleton.as_deref()
    }

    /// Check if the domain is a well-known freemail provider.
    pub fn is_freemail(&self) -> bool {
        is_freemail_domain(&self.domain)
    }
}

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display_name {
            Some(name) => write!(
                f,
                "\"{}\" <{}@{}>",
                escape_display_name(name),
                self.local_part,
                self.domain
            ),
            None => write!(f, "{}@{}", self.local_part, self.domain),
        }
    }
}

/// Escape a display name for safe inclusion in a quoted string.
///
/// Backslash-escapes `"` and `\`, and strips bare CR/LF to prevent
/// header injection in serialized output.
fn escape_display_name(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            '"' => {
                escaped.push('\\');
                escaped.push('"');
            }
            '\\' => {
                escaped.push('\\');
                escaped.push('\\');
            }
            '\r' | '\n' => {} // strip CRLF
            _ => escaped.push(ch),
        }
    }
    escaped
}

impl PartialEq for EmailAddress {
    fn eq(&self, other: &Self) -> bool {
        self.local_part == other.local_part && self.domain == other.domain
    }
}

impl Eq for EmailAddress {}

impl std::hash::Hash for EmailAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.local_part.hash(state);
        self.domain.hash(state);
    }
}

impl std::str::FromStr for EmailAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_with(s, &Config::default())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EmailAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.canonical().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EmailAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Check if a domain is a well-known freemail provider.
fn is_freemail_domain(domain: &str) -> bool {
    matches!(
        domain,
        "gmail.com"
            | "googlemail.com"
            | "yahoo.com"
            | "yahoo.co.uk"
            | "yahoo.co.jp"
            | "outlook.com"
            | "hotmail.com"
            | "live.com"
            | "msn.com"
            | "aol.com"
            | "protonmail.com"
            | "proton.me"
            | "icloud.com"
            | "me.com"
            | "mac.com"
            | "mail.com"
            | "zoho.com"
            | "yandex.ru"
            | "yandex.com"
            | "mail.ru"
            | "gmx.com"
            | "gmx.de"
            | "web.de"
            | "tutanota.com"
            | "tuta.io"
            | "fastmail.com"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FromStr (default config) ──

    #[test]
    fn parse_simple() {
        let email: EmailAddress = "user@example.com".parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(email.local_part(), "user");
        assert_eq!(email.domain(), "example.com");
        assert_eq!(email.tag(), None);
        assert_eq!(email.canonical(), "user@example.com");
    }

    #[test]
    fn parse_with_tag() {
        let email: EmailAddress = "user+newsletter@example.com"
            .parse()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(email.local_part(), "user+newsletter");
        assert_eq!(email.tag(), Some("newsletter"));
    }

    #[test]
    fn display_format() {
        let email: EmailAddress = "user@example.com".parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(format!("{email}"), "user@example.com");
    }

    #[test]
    fn equality_by_canonical() {
        let a: EmailAddress = "user@example.com".parse().unwrap_or_else(|e| panic!("{e}"));
        let b: EmailAddress = "user@Example.COM".parse().unwrap_or_else(|e| panic!("{e}"));
        // Default config: domain-only lowercase, so local parts same case → equal
        assert_eq!(a, b);
    }

    #[test]
    fn freemail_detection() {
        let email: EmailAddress = "user@gmail.com".parse().unwrap_or_else(|e| panic!("{e}"));
        assert!(email.is_freemail());

        let email: EmailAddress = "user@company.com".parse().unwrap_or_else(|e| panic!("{e}"));
        assert!(!email.is_freemail());
    }

    // ── Configured parsing ──

    #[test]
    fn full_normalization_pipeline() {
        let config = Config::builder()
            .strip_subaddress()
            .dots_gmail_only()
            .lowercase_all()
            .check_confusables()
            .build();

        let email = EmailAddress::parse_with("A.L.I.C.E+promo@Gmail.COM", &config)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(email.canonical(), "alice@gmail.com");
        assert_eq!(email.tag(), Some("promo"));
        assert!(email.skeleton().is_some());
    }

    #[test]
    fn display_name_parsing() {
        let config = Config::builder().allow_display_name().build();

        let email = EmailAddress::parse_with("John Doe <user@example.com>", &config)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(email.display_name(), Some("John Doe"));
        assert_eq!(email.local_part(), "user");
        assert_eq!(email.domain(), "example.com");
    }

    // ── Serde ──

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip() {
        let email: EmailAddress = "user@example.com".parse().unwrap_or_else(|e| panic!("{e}"));
        let json = serde_json::to_string(&email).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(json, "\"user@example.com\"");

        let back: EmailAddress = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(email, back);
    }

    // ── Validation errors ──

    #[test]
    fn rejects_empty() {
        let result: Result<EmailAddress, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_no_domain_dot() {
        let result: Result<EmailAddress, _> = "user@localhost".parse();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err().kind(), ErrorKind::DomainNoDot));
    }

    #[test]
    fn allows_single_label_when_configured() {
        let config = Config::builder().allow_single_label_domain().build();
        let email =
            EmailAddress::parse_with("user@localhost", &config).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(email.domain(), "localhost");
    }
}
