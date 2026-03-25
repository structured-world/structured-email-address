//! Email address normalization.
//!
//! Converts parsed email addresses to canonical form based on [`Config`] settings.
//! Adapted from StructuredID's `sid-authn/normalize.rs` with generalized provider support.

use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;

use crate::config::{CasePolicy, Config, DotPolicy, SubaddressPolicy};
use crate::error::{Error, ErrorKind};
use crate::parser::Parsed;

/// Result of normalization: owned canonical parts.
#[derive(Debug, Clone)]
pub(crate) struct Normalized {
    /// Canonical local part (after tag stripping, dot removal, case folding).
    pub local_part: String,
    /// Extracted subaddress tag, if any (before stripping).
    pub tag: Option<String>,
    /// Canonical domain (after IDNA encoding, case folding).
    pub domain: String,
    /// Display name from the original, if present.
    pub display_name: Option<String>,
    /// Confusable skeleton of the local part (for homoglyph detection).
    pub skeleton: Option<String>,
}

/// Normalize a parsed email address according to the given config.
pub(crate) fn normalize(parsed: &Parsed<'_>, config: &Config) -> Result<Normalized, Error> {
    let raw_local = parsed.local_part.as_str(parsed.input);
    let raw_domain = parsed.domain.as_str(parsed.input);
    let is_quoted = raw_local.starts_with('"') && raw_local.ends_with('"');

    // Strip quotes and unescape RFC quoted-pairs from quoted-string local parts.
    let unquoted_local = if is_quoted {
        unescape_quoted_string(&raw_local[1..raw_local.len() - 1])
    } else {
        raw_local.to_string()
    };

    // Step 1: Unicode NFC normalization.
    let nfc_local: String = unquoted_local.nfc().collect();
    let nfc_domain: String = raw_domain.nfc().collect();

    // Step 2: Case folding.
    let cased_local = match config.case_policy {
        CasePolicy::All => nfc_local.to_lowercase(),
        CasePolicy::Domain | CasePolicy::Preserve => nfc_local,
    };

    // Steps 3-5: Subaddress and dot normalization apply only to unquoted local-parts.
    // Inside a quoted-string, '+' and '.' are literal characters, not provider semantics.
    let (_base_local, tag, local_after_dots) = if is_quoted {
        (cased_local.clone(), None, cased_local)
    } else {
        // Step 3: Extract subaddress tag.
        let sep = config.subaddress_separator;
        let (base, tag) = match cased_local.split_once(sep) {
            Some((base, tag)) if !base.is_empty() => (base.to_string(), Some(tag.to_string())),
            _ => (cased_local, None),
        };

        // Step 4: Apply subaddress policy to canonical form.
        let local_after_tag = match config.subaddress {
            SubaddressPolicy::Strip => base.clone(),
            SubaddressPolicy::Preserve => match &tag {
                Some(t) => format!("{}{}{}", base, sep, t),
                None => base.clone(),
            },
        };

        // Step 5: Dot policy.
        let after_dots = apply_dot_policy(&local_after_tag, &nfc_domain, config.dot_policy);
        (base, tag, after_dots)
    };

    // Step 6: Domain — IDNA encoding (punycode for international domains).
    // Domain literals (e.g., [192.168.1.1]) are IP addresses, not hostnames — skip IDNA.
    // Use strict mode: STD3 ASCII deny-list, hyphen checks, DNS length verification.
    let canonical_domain = if nfc_domain.starts_with('[') {
        nfc_domain.to_lowercase()
    } else {
        idna::domain_to_ascii_strict(&nfc_domain).map_err(|e| {
            Error::new(
                ErrorKind::IdnaError(format!("{}: {}", nfc_domain, e)),
                parsed.domain.start,
            )
        })?
    };

    // Step 7: Anti-homoglyph skeleton (optional).
    let skel = if config.check_confusables {
        Some(confusable_skeleton(&local_after_dots))
    } else {
        None
    };

    // Display name — unescape quoted-pairs and collapse FWS so the stored
    // value represents the semantic name, not raw RFC syntax.
    let display_name = parsed
        .display_name
        .map(|span| unescape_quoted_string(span.as_str(parsed.input)));

    Ok(Normalized {
        local_part: local_after_dots,
        tag,
        domain: canonical_domain,
        display_name,
        skeleton: skel,
    })
}

/// Apply dot-stripping policy.
fn apply_dot_policy(local: &str, domain: &str, policy: DotPolicy) -> String {
    match policy {
        DotPolicy::Preserve => local.to_string(),
        DotPolicy::Always => local.replace('.', ""),
        DotPolicy::GmailOnly => {
            if is_gmail_domain(domain) {
                local.replace('.', "")
            } else {
                local.to_string()
            }
        }
    }
}

/// Check if domain is a Gmail domain (case-insensitive, allocation-free).
fn is_gmail_domain(domain: &str) -> bool {
    domain.eq_ignore_ascii_case("gmail.com") || domain.eq_ignore_ascii_case("googlemail.com")
}

/// Remove RFC 5322 quoted-pair backslashes (`\"` → `"`, `\\` → `\`)
/// and collapse FWS (CRLF + WSP) to a single space.
fn unescape_quoted_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            // Consume the escaped character (or keep backslash if at end).
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            } else {
                out.push(ch);
            }
        } else if ch == '\r' {
            // Collapse FWS (CRLF + WSP) to a single space.
            if chars.peek() == Some(&'\n') {
                chars.next(); // consume '\n'
                // Skip all following WSP
                while matches!(chars.peek(), Some(' ' | '\t')) {
                    chars.next();
                }
                out.push(' ');
            }
            // Bare CR without LF: skip (shouldn't appear per parser validation).
        } else if ch == '\n' {
            // Bare LF: skip (shouldn't appear per parser validation).
        } else {
            out.push(ch);
        }
    }
    out
}

/// Compute confusable skeleton for anti-homoglyph protection.
///
/// Two strings with the same skeleton are visually confusable.
/// Use during registration to prevent lookalike accounts.
pub fn confusable_skeleton(input: &str) -> String {
    let nfc: String = input.nfc().collect();
    skeleton(&nfc).collect::<String>().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::parser;

    fn parse_and_normalize(input: &str, config: &Config) -> Normalized {
        let parsed = parser::parse(
            input,
            config.strictness,
            config.allow_display_name,
            config.allow_domain_literal,
        )
        .unwrap_or_else(|e| panic!("parse failed for '{input}': {e}"));
        normalize(&parsed, config).unwrap_or_else(|e| panic!("normalize failed for '{input}': {e}"))
    }

    #[test]
    fn basic_normalization() {
        let config = Config::default();
        let n = parse_and_normalize("User@Example.COM", &config);
        assert_eq!(n.local_part, "User"); // Domain-only lowercase by default
        assert_eq!(n.domain, "example.com");
    }

    #[test]
    fn lowercase_all() {
        let config = Config::builder().lowercase_all().build();
        let n = parse_and_normalize("User@Example.COM", &config);
        assert_eq!(n.local_part, "user");
        assert_eq!(n.domain, "example.com");
    }

    #[test]
    fn subaddress_extraction() {
        let config = Config::default();
        let n = parse_and_normalize("user+promo@example.com", &config);
        assert_eq!(n.tag, Some("promo".to_string()));
        // Preserved by default
        assert_eq!(n.local_part, "user+promo");
    }

    #[test]
    fn subaddress_strip() {
        let config = Config::builder().strip_subaddress().lowercase_all().build();
        let n = parse_and_normalize("user+promo@example.com", &config);
        assert_eq!(n.tag, Some("promo".to_string()));
        assert_eq!(n.local_part, "user");
    }

    #[test]
    fn gmail_dot_stripping() {
        let config = Config::builder().dots_gmail_only().lowercase_all().build();

        let n = parse_and_normalize("a.l.i.c.e@gmail.com", &config);
        assert_eq!(n.local_part, "alice");

        // Non-gmail: dots preserved
        let n = parse_and_normalize("a.l.i.c.e@example.com", &config);
        assert_eq!(n.local_part, "a.l.i.c.e");
    }

    #[test]
    fn idna_domain() {
        let config = Config::default();
        let n = parse_and_normalize("user@münchen.de", &config);
        assert_eq!(n.domain, "xn--mnchen-3ya.de");
    }

    #[test]
    fn idna_error_propagated() {
        // Verify that IDNA encoding failure produces IdnaError.
        // A label exceeding 63 bytes fails DNS length verification in strict mode.
        use crate::parser::Span;
        let long_label = "a".repeat(64);
        let input = format!("user@{long_label}.com");
        let config = Config::default();
        let parsed = crate::parser::Parsed {
            input: &input,
            display_name: None,
            local_part: Span { start: 0, end: 4 },
            domain: Span {
                start: 5,
                end: input.len(),
            },
            comments: vec![],
        };
        let err = normalize(&parsed, &config).unwrap_err();
        assert!(
            matches!(err.kind(), ErrorKind::IdnaError(_)),
            "expected IdnaError, got {:?}",
            err.kind()
        );
    }

    #[test]
    fn confusable_skeleton_cyrillic() {
        // Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
        let latin = confusable_skeleton("alice");
        let cyrillic = confusable_skeleton("\u{0430}lice");
        assert_eq!(latin, cyrillic);
    }

    #[test]
    fn quoted_local_unescapes_quoted_pairs() {
        // RFC 5322 quoted-pairs: "a\ b" and "a b" are semantically equivalent.
        let config = Config::default();
        let n1 = parse_and_normalize("\"a\\ b\"@example.com", &config);
        let n2 = parse_and_normalize("\"a b\"@example.com", &config);
        assert_eq!(
            n1.local_part, n2.local_part,
            "quoted-pair backslash must be unescaped"
        );
        assert_eq!(n1.local_part, "a b");
    }

    #[test]
    fn quoted_local_preserves_plus_and_dots() {
        // Quoted-string locals: literal '+' and '.' are NOT provider semantics.
        // "a+b"@example.com is a distinct mailbox — subaddress extraction must NOT split on '+'.
        let config = Config::builder()
            .strip_subaddress()
            .dots_gmail_only()
            .lowercase_all()
            .build();
        let n = parse_and_normalize("\"a+b\"@gmail.com", &config);
        assert_eq!(
            n.local_part, "a+b",
            "subaddress must not split inside quoted local"
        );
        assert_eq!(n.tag, None, "no tag extraction for quoted local");

        // Dots inside quoted local must not be stripped even for Gmail.
        let n = parse_and_normalize("\"a.b\"@gmail.com", &config);
        assert_eq!(
            n.local_part, "a.b",
            "dots must not be stripped inside quoted local"
        );
    }

    #[test]
    fn full_pipeline() {
        let config = Config::builder()
            .strip_subaddress()
            .dots_gmail_only()
            .lowercase_all()
            .check_confusables()
            .build();

        let n = parse_and_normalize("A.L.I.C.E+promo@Gmail.COM", &config);
        assert_eq!(n.local_part, "alice");
        assert_eq!(n.tag, Some("promo".to_string()));
        assert_eq!(n.domain, "gmail.com");
        assert!(n.skeleton.is_some());
    }
}
