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
fn display_name_escaping() {
    let config = Config::builder().allow_display_name().build();
    // Display name with quotes should be escaped
    let email = EmailAddress::parse_with("John \"Johnny\" Doe <user@example.com>", &config)
        .unwrap_or_else(|e| panic!("{e}"));
    let formatted = format!("{email}");
    assert!(
        formatted.contains("\\\"Johnny\\\""),
        "Expected escaped quotes in: {formatted}"
    );
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

#[test]
fn freemail_via_custom_provider() {
    // A registered custom provider marked freemail is reported by is_freemail().
    use crate::ProviderRule;
    let config = Config::builder()
        .add_provider(ProviderRule::new(["freebie.example"]).freemail(true))
        .build();
    let email =
        EmailAddress::parse_with("user@freebie.example", &config).unwrap_or_else(|e| panic!("{e}"));
    assert!(email.is_freemail());
}

// ── Provider-aware normalization (#5) ──

#[test]
fn provider_aware_gmail_normalizes_by_rule() {
    // provider_aware applies Gmail's rule (strip dots, fold case, '+' tag)
    // without setting any global dot/case policy. strip_subaddress drops the
    // extracted tag from the canonical form.
    let config = Config::builder()
        .provider_aware()
        .strip_subaddress()
        .build();
    let email = EmailAddress::parse_with("A.Li.Ce+promo@Gmail.com", &config)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "alice");
    assert_eq!(email.tag(), Some("promo"));
    assert_eq!(email.domain(), "gmail.com");
}

#[test]
fn provider_aware_gmail_preserves_tag_by_default() {
    // Default subaddress policy keeps the tag in the canonical local part;
    // dots are still stripped and case folded by the Gmail rule.
    let config = Config::builder().provider_aware().build();
    let email = EmailAddress::parse_with("A.Li.Ce+promo@Gmail.com", &config)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "alice+promo");
    assert_eq!(email.tag(), Some("promo"));
}

#[test]
fn provider_aware_leaves_non_provider_domains_to_global_policy() {
    // A non-provider domain is untouched by provider rules: dots preserved,
    // local-part case preserved (global defaults).
    let config = Config::builder().provider_aware().build();
    let email = EmailAddress::parse_with("A.L.I.C.E@example.com", &config)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "A.L.I.C.E");
    assert_eq!(email.domain(), "example.com");
}

#[test]
fn provider_aware_quoted_local_preserves_case() {
    // A quoted local-part is literal: the provider rule's case folding
    // (Gmail) must NOT apply inside it, just as dots and the subaddress
    // separator don't. Without a global lowercase policy, case is preserved.
    let config = Config::builder().provider_aware().build();
    let email =
        EmailAddress::parse_with("\"A.B\"@gmail.com", &config).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "A.B");

    // A global lowercase policy is not provider-specific, so it still folds
    // a quoted local-part — even when a provider rule matches (the rule's
    // own folding is skipped for quoted, but the global policy still applies).
    let config = Config::builder().provider_aware().lowercase_all().build();
    let email =
        EmailAddress::parse_with("\"A.B\"@gmail.com", &config).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "a.b");
}

#[test]
fn provider_aware_off_does_not_strip_gmail_dots() {
    // Without provider_aware and without dots_gmail_only, gmail dots stay.
    let email: EmailAddress = "a.b.c@gmail.com".parse().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "a.b.c");
}

#[test]
fn custom_provider_aware_rule_applies() {
    use crate::ProviderRule;
    // Custom provider: strips dots, '-' separator.
    let config = Config::builder()
        .provider_aware()
        .strip_subaddress()
        .add_provider(
            ProviderRule::new(["corp.example"])
                .strip_dots(true)
                .lowercase_local(true)
                .subaddress_separator(Some('-')),
        )
        .build();
    let email = EmailAddress::parse_with("John.Doe-tag@corp.example", &config)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "johndoe");
    assert_eq!(email.tag(), Some("tag"));
}

#[test]
fn idn_provider_rule_consistent_across_normalization_and_freemail() {
    use crate::ProviderRule;
    // A provider rule registered with the Unicode domain must apply to the
    // IDNA-encoded address for BOTH provider-aware normalization and
    // is_freemail() — the canonical domain is used at both call sites.
    let config = Config::builder()
        .provider_aware()
        .add_provider(
            ProviderRule::new(["münchen.de"])
                .strip_dots(true)
                .lowercase_local(true)
                .freemail(true),
        )
        .build();
    let email =
        EmailAddress::parse_with("A.B@münchen.de", &config).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.domain(), "xn--mnchen-3ya.de");
    assert_eq!(
        email.local_part(),
        "ab",
        "provider rule strips dots + folds case"
    );
    assert!(email.is_freemail(), "same rule drives is_freemail");
}

#[test]
fn dots_gmail_only_ignores_custom_providers() {
    use crate::ProviderRule;
    // GmailOnly is a legacy mode tied to the built-in dot-stripping providers
    // (Gmail/Googlemail). Custom providers affect normalization ONLY under
    // provider_aware(); a custom strip_dots rule must NOT leak into GmailOnly
    // when provider_aware is off.
    let config = Config::builder()
        .dots_gmail_only()
        .add_provider(ProviderRule::new(["corp.example"]).strip_dots(true))
        .build();

    // The custom provider's strip_dots is ignored: dots are preserved.
    let email =
        EmailAddress::parse_with("a.b@corp.example", &config).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "a.b");

    // Built-in Gmail still strips dots under GmailOnly.
    let email =
        EmailAddress::parse_with("a.b.c@gmail.com", &config).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.local_part(), "abc");
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

#[test]
fn leading_comment_full_pipeline() {
    // #40: a leading RFC 5322 comment before the local-part must parse
    // end-to-end, with the comment stripped from the canonical address.
    let config = Config::builder()
        .strictness(Strictness::Lax)
        .allow_display_name()
        .allow_domain_literal()
        .allow_single_label_domain()
        .lowercase_all()
        .build();

    for input in [
        "(comment)jane.smith@example.com",
        "jane(comment).smith@example.com",
        "jane.smith(comment)@example.com",
        "jane.smith@example.com",
    ] {
        let email = EmailAddress::parse_with(input, &config)
            .unwrap_or_else(|e| panic!("'{input}' must parse: {e}"));
        assert_eq!(email.canonical(), "jane.smith@example.com");
    }
}

#[test]
fn rejects_newline_in_address() {
    // Header-injection hardening: a trailing newline must not be silently
    // accepted (it previously survived an over-eager input.trim()).
    let config = Config::default();
    assert!("user@example.com\n".parse::<EmailAddress>().is_err());
    assert!(EmailAddress::parse_with("user@example.com\r\n", &config).is_err());
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

// ── Batch parsing ──

#[test]
fn batch_parse_mixed_results() {
    // Verifies that parse_batch returns Ok for valid and Err for invalid
    // inputs, preserving input order.
    let config = Config::default();
    let results = EmailAddress::parse_batch(
        &["alice@example.com", "invalid", "bob@example.org"],
        &config,
    );
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());
    assert_eq!(results[0].as_ref().map(|e| e.domain()), Ok("example.com"));
    assert_eq!(results[2].as_ref().map(|e| e.domain()), Ok("example.org"));
}

#[test]
fn batch_parse_empty_input() {
    // Empty slice returns empty vec.
    let config = Config::default();
    let results = EmailAddress::parse_batch(&[], &config);
    assert!(results.is_empty());
}

#[test]
fn batch_parse_all_valid() {
    // Batch of valid addresses all succeed.
    let config = Config::default();
    let inputs = &["a@b.com", "x@y.org", "test+tag@example.com"];
    let results = EmailAddress::parse_batch(inputs, &config);
    assert!(results.iter().all(|r| r.is_ok()));
}

#[test]
fn batch_parse_all_invalid() {
    // Batch of invalid addresses all fail.
    let config = Config::default();
    let results = EmailAddress::parse_batch(&["", "noatsign", "@missing-local.com"], &config);
    assert!(results.iter().all(|r| r.is_err()));
}

#[test]
fn batch_parse_with_config() {
    // Batch parsing respects config (e.g., subaddress stripping).
    let config = Config::builder()
        .strip_subaddress()
        .dots_gmail_only()
        .lowercase_all()
        .build();
    let results =
        EmailAddress::parse_batch(&["A.L.I.C.E+promo@Gmail.COM", "BOB@example.com"], &config);
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].as_ref().map(|e| e.canonical()),
        Ok("alice@gmail.com".to_string())
    );
    assert_eq!(
        results[1].as_ref().map(|e| e.canonical()),
        Ok("bob@example.com".to_string())
    );
}

// ── domain_unicode() accessor ──

#[test]
fn domain_unicode_roundtrip() {
    // IDN domain: input Unicode → domain() punycode → domain_unicode() back to Unicode.
    let email: EmailAddress = "user@münchen.de".parse().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.domain(), "xn--mnchen-3ya.de");
    assert_eq!(email.domain_unicode(), "münchen.de");
}

#[test]
fn domain_unicode_ascii_fallback() {
    // ASCII domain: domain_unicode() returns same as domain().
    let email: EmailAddress = "user@example.com".parse().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.domain_unicode(), "example.com");
    assert_eq!(email.domain_unicode(), email.domain());
}

#[test]
fn domain_unicode_mixed_labels() {
    // Domain with one IDN label and one ASCII label.
    let email: EmailAddress = "user@über.example.com"
        .parse()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(email.domain(), "xn--ber-goa.example.com");
    assert_eq!(email.domain_unicode(), "über.example.com");
}

#[test]
fn domain_unicode_japanese() {
    // Japanese domain roundtrip.
    let email: EmailAddress = "user@例え.jp".parse().unwrap_or_else(|e| panic!("{e}"));
    assert!(email.domain().contains("xn--"));
    assert_eq!(email.domain_unicode(), "例え.jp");
}

#[cfg(feature = "rayon")]
#[test]
fn batch_par_matches_sequential() {
    // Parallel variant produces identical results to sequential.
    let config = Config::builder().strip_subaddress().lowercase_all().build();
    let inputs = &[
        "alice@example.com",
        "invalid",
        "BOB+tag@Example.ORG",
        "",
        "user@test.com",
    ];
    let seq = EmailAddress::parse_batch(inputs, &config);
    let par = EmailAddress::parse_batch_par(inputs, &config);
    assert_eq!(seq.len(), par.len());
    for (i, (s, p)) in seq.iter().zip(par.iter()).enumerate() {
        match (s, p) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "result {i} diverges"),
            (Err(a), Err(b)) => assert_eq!(a, b, "error {i} diverges: {a} vs {b}"),
            _ => panic!("result {i}: one Ok, one Err"),
        }
    }
}
