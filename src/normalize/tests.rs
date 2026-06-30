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
    assert_eq!(n.domain_unicode.as_deref(), Some("münchen.de"));
}

#[test]
fn ascii_domain_no_unicode_field() {
    let config = Config::default();
    let n = parse_and_normalize("user@example.com", &config);
    assert_eq!(n.domain, "example.com");
    assert_eq!(n.domain_unicode, None);
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
        local_part_clean: None,
        domain_clean: None,
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

#[test]
fn obs_cfws_stripped_before_normalization() {
    // Verify that CFWS-stripped content flows through case folding.
    let config = Config::builder()
        .strictness(crate::Strictness::Lax)
        .lowercase_all()
        .build();
    let n = parse_and_normalize("User (comment) . Name@Example (c) . COM", &config);
    assert_eq!(n.local_part, "user.name", "CFWS stripped + lowercased");
    assert_eq!(n.domain, "example.com", "domain CFWS stripped + lowercased");
}

#[test]
fn obs_cfws_stripped_with_idna() {
    // Verify CFWS stripping flows through IDNA encoding.
    let config = Config::builder()
        .strictness(crate::Strictness::Lax)
        .lowercase_all()
        .build();
    let n = parse_and_normalize("user@münchen (comment) . de", &config);
    assert_eq!(n.domain, "xn--mnchen-3ya.de");
    assert_eq!(n.domain_unicode.as_deref(), Some("münchen.de"));
}
