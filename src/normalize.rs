//! Email address normalization.
//!
//! Converts parsed email addresses to canonical form based on [`Config`] settings.
//! Adapted from StructuredID's `sid-authn/normalize.rs` with generalized provider support.

use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;

use crate::config::{CasePolicy, Config, DotPolicy, SubaddressPolicy};
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
pub(crate) fn normalize(parsed: &Parsed<'_>, config: &Config) -> Normalized {
    let raw_local = parsed.local_part.as_str(parsed.input);
    let raw_domain = parsed.domain.as_str(parsed.input);

    // Strip quotes from quoted-string local parts for normalization.
    let unquoted_local = raw_local
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(raw_local);

    // Step 1: Unicode NFC normalization.
    let nfc_local: String = unquoted_local.nfc().collect();
    let nfc_domain: String = raw_domain.nfc().collect();

    // Step 2: Case folding.
    let cased_local = match config.case_policy {
        CasePolicy::All => nfc_local.to_lowercase(),
        CasePolicy::Domain | CasePolicy::Preserve => nfc_local,
    };

    // Step 3: Extract subaddress tag.
    let sep = config.subaddress_separator;
    let (base_local, tag) = match cased_local.split_once(sep) {
        // Only extract tag if there's a non-empty base (e.g., "+tag" has empty base → no split).
        Some((base, tag)) if !base.is_empty() => (base.to_string(), Some(tag.to_string())),
        _ => (cased_local, None),
    };

    // Step 4: Apply subaddress policy to canonical form.
    let local_after_tag = match config.subaddress {
        SubaddressPolicy::Strip => base_local.clone(),
        SubaddressPolicy::Preserve => match &tag {
            Some(t) => format!("{}{}{}", base_local, sep, t),
            None => base_local.clone(),
        },
    };

    // Step 5: Dot policy.
    let local_after_dots = apply_dot_policy(&local_after_tag, &nfc_domain, config.dot_policy);

    // Step 6: Domain — IDNA encoding (punycode for international domains).
    // IDNA can fail for legitimate Unicode domains that lack a punycode mapping
    // (e.g., labels with non-IDNA2008 characters). Falling back to NFC lowercase
    // preserves the domain in a usable canonical form rather than rejecting it.
    let canonical_domain =
        idna::domain_to_ascii(&nfc_domain).unwrap_or_else(|_| nfc_domain.to_lowercase());

    // Step 7: Domain case (always lowercase per RFC).
    let canonical_domain = canonical_domain.to_lowercase();

    // Step 8: Anti-homoglyph skeleton (optional).
    let skel = if config.check_confusables {
        Some(confusable_skeleton(&local_after_dots))
    } else {
        None
    };

    // Display name
    let display_name = parsed
        .display_name
        .map(|span| span.as_str(parsed.input).to_string());

    Normalized {
        local_part: local_after_dots,
        tag,
        domain: canonical_domain,
        display_name,
        skeleton: skel,
    }
}

/// Apply dot-stripping policy.
fn apply_dot_policy(local: &str, domain: &str, policy: DotPolicy) -> String {
    match policy {
        DotPolicy::Preserve => local.to_string(),
        DotPolicy::Always => local.replace('.', ""),
        DotPolicy::GmailOnly => {
            let domain_lower = domain.to_lowercase();
            if is_gmail_domain(&domain_lower) {
                local.replace('.', "")
            } else {
                local.to_string()
            }
        }
    }
}

/// Check if domain is a Gmail domain (ignores dots in local part).
fn is_gmail_domain(domain: &str) -> bool {
    matches!(domain, "gmail.com" | "googlemail.com")
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
        normalize(&parsed, config)
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
    fn confusable_skeleton_cyrillic() {
        // Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
        let latin = confusable_skeleton("alice");
        let cyrillic = confusable_skeleton("\u{0430}lice");
        assert_eq!(latin, cyrillic);
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
