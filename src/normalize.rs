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
    /// Unicode form of the domain (only populated when domain has punycode labels).
    pub domain_unicode: Option<String>,
    /// Display name from the original, if present.
    pub display_name: Option<String>,
    /// Confusable skeleton of the local part (for homoglyph detection).
    pub skeleton: Option<String>,
}

/// Normalize a parsed email address according to the given config.
pub(crate) fn normalize(parsed: &Parsed<'_>, config: &Config) -> Result<Normalized, Error> {
    // Semantic local-part and domain: CFWS-stripped for obs-forms, raw span otherwise.
    let local = parsed.local_part_str();
    let domain_str = parsed.domain_str();
    let is_quoted = local.starts_with('"') && local.ends_with('"');

    // Strip quotes and unescape RFC quoted-pairs from quoted-string local parts.
    let unquoted_local = if is_quoted {
        unescape_quoted_string(&local[1..local.len() - 1])
    } else {
        local.to_string()
    };

    // Step 1: Unicode NFC normalization.
    let nfc_local: String = unquoted_local.nfc().collect();
    let nfc_domain: String = domain_str.nfc().collect();

    // Canonical (IDNA-ASCII) domain — computed up front so provider lookup,
    // freemail detection (in parse_with), and the final domain all use the SAME
    // form. Domain literals ([192.168.1.1]) are IPs, not hostnames — skip IDNA.
    // Strict mode: STD3 ASCII deny-list, hyphen checks, DNS length verification.
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

    // Provider-aware overrides: when enabled and the domain matches a registered
    // provider, that rule's case / separator / dot policy governs this address
    // instead of the global policies. Non-matching domains use the global policies.
    // Lookup uses the canonical domain so IDN rules match consistently.
    let provider = if config.provider_aware {
        config.providers.lookup(&canonical_domain)
    } else {
        None
    };

    // Step 2: Case folding (provider rule overrides the global case policy).
    // A quoted local-part is literal, so provider semantics never apply inside
    // it (same as dots/subaddress below) — only a global lowercase policy does.
    let lowercase_local = match provider {
        Some(p) if !is_quoted => p.folds_case(),
        _ => matches!(config.case_policy, CasePolicy::All),
    };
    let cased_local = if lowercase_local {
        nfc_local.to_lowercase()
    } else {
        nfc_local
    };

    // Steps 3-5: Subaddress and dot normalization apply only to unquoted local-parts.
    // Inside a quoted-string, '+' and '.' are literal characters, not provider semantics.
    let (_base_local, tag, local_after_dots) = if is_quoted {
        (cased_local.clone(), None, cased_local)
    } else {
        // Step 3: Extract subaddress tag. A provider with no subaddressing
        // (separator None) disables tag extraction.
        let sep: Option<char> = match provider {
            Some(p) => p.separator(),
            None => Some(config.subaddress_separator),
        };
        let (base, tag) = match sep {
            Some(s) => match cased_local.split_once(s) {
                Some((base, tag)) if !base.is_empty() => (base.to_string(), Some(tag.to_string())),
                _ => (cased_local, None),
            },
            None => (cased_local, None),
        };

        // Step 4: Apply subaddress policy to canonical form.
        let local_after_tag = match config.subaddress {
            SubaddressPolicy::Strip => base.clone(),
            SubaddressPolicy::Preserve => match (&tag, sep) {
                (Some(t), Some(s)) => format!("{base}{s}{t}"),
                _ => base.clone(),
            },
        };

        // Step 5: Dot stripping (provider rule overrides the global dot policy).
        let strip = match provider {
            Some(p) => p.strips_dots(),
            None => match config.dot_policy {
                DotPolicy::Preserve => false,
                DotPolicy::Always => true,
                // Strip only for a BUILT-IN provider that ignores dots
                // (Gmail/Googlemail). Custom providers affect normalization only
                // under provider_aware(), so the legacy GmailOnly mode consults
                // the built-in registry, never config.providers.
                DotPolicy::GmailOnly => crate::provider::builtin_ref()
                    .lookup(&canonical_domain)
                    .is_some_and(|p| p.strips_dots()),
            },
        };
        let after_dots = if strip {
            local_after_tag.replace('.', "")
        } else {
            local_after_tag
        };
        (base, tag, after_dots)
    };

    // Step 6: IDNA roundtrip — recover Unicode domain when punycode is present.
    let domain_unicode = if canonical_domain
        .split('.')
        .any(|label| label.starts_with("xn--"))
    {
        let (unicode, result) = idna::domain_to_unicode(&canonical_domain);
        if result.is_ok() && unicode != canonical_domain {
            Some(unicode)
        } else {
            None
        }
    } else {
        None
    };

    // Step 8: Anti-homoglyph skeleton (optional).
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
        domain_unicode,
        display_name,
        skeleton: skel,
    })
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
                chars.next(); // consume '\n', then skip all following WSP
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
mod tests;
