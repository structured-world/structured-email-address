use super::*;

fn parse_ok(input: &str) -> Parsed<'_> {
    parse(input, Strictness::Standard, false, false)
        .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"))
}

fn parse_ok_lax(input: &str) -> Parsed<'_> {
    parse(input, Strictness::Lax, false, false)
        .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"))
}

fn parse_err(input: &str) -> Error {
    parse(input, Strictness::Standard, false, false)
        .expect_err(&format!("expected error for '{input}'"))
}

// ── Basic valid addresses ──

#[test]
fn simple_address() {
    let p = parse_ok("user@example.com");
    assert_eq!(p.local_part.as_str(p.input), "user");
    assert_eq!(p.domain.as_str(p.input), "example.com");
}

#[test]
fn subaddress_preserved() {
    let p = parse_ok("user+tag@example.com");
    assert_eq!(p.local_part.as_str(p.input), "user+tag");
}

#[test]
fn dotted_local() {
    let p = parse_ok("first.last@example.com");
    assert_eq!(p.local_part.as_str(p.input), "first.last");
}

#[test]
fn utf8_local() {
    let p = parse_ok("дмитрий@example.com");
    assert_eq!(p.local_part.as_str(p.input), "дмитрий");
}

#[test]
fn utf8_domain() {
    let p = parse_ok("user@münchen.de");
    assert_eq!(p.domain.as_str(p.input), "münchen.de");
}

#[test]
fn quoted_local_part() {
    let p = parse_ok("\"user@name\"@example.com");
    assert_eq!(p.local_part.as_str(p.input), "\"user@name\"");
}

#[test]
fn quoted_local_with_spaces() {
    let p = parse_ok("\"user name\"@example.com");
    assert_eq!(p.local_part.as_str(p.input), "\"user name\"");
}

// ── Invalid addresses ──

#[test]
fn empty_input() {
    let e = parse_err("");
    assert_eq!(e.kind(), &ErrorKind::Empty);
}

#[test]
fn no_at_sign() {
    let e = parse_err("userexample.com");
    assert_eq!(e.kind(), &ErrorKind::MissingAtSign);
}

#[test]
fn empty_local() {
    let e = parse_err("@example.com");
    assert_eq!(e.kind(), &ErrorKind::EmptyLocalPart);
}

#[test]
fn empty_domain() {
    let e = parse_err("user@");
    assert_eq!(e.kind(), &ErrorKind::EmptyDomain);
}

// ── Dot-atom edge cases ──

#[test]
fn trailing_dot_in_local_part_is_not_missing_at_sign() {
    let e = parse_err("user.@example.com");
    // Ensure this is treated as a local-part syntax error, not as a missing '@'.
    assert_ne!(e.kind(), &ErrorKind::MissingAtSign);
}

#[test]
fn obs_local_part_quoted_first_word() {
    // obs-local-part: word *("." word), where word can be quoted-string.
    // "a".b@example.com must parse in Lax mode.
    let p = parse("\"a\".b@example.com", Strictness::Lax, false, false).unwrap_or_else(|e| {
        panic!("Lax must accept obs-local-part starting with quoted word: {e}")
    });
    assert_eq!(p.local_part.as_str(p.input), "\"a\".b");
    assert_eq!(p.domain.as_str(p.input), "example.com");
}

#[test]
fn obs_local_part_rejected_in_standard() {
    let e = parse("a.\"b\"@example.com", Strictness::Standard, false, false)
        .expect_err("expected obs-local-part to be rejected in Standard strictness");
    // Should fail due to local-part syntax, not due to a missing '@'.
    assert_ne!(e.kind(), &ErrorKind::MissingAtSign);
}

#[test]
fn obs_local_part_accepted_in_lax() {
    let p = parse("a.\"b\"@example.com", Strictness::Lax, false, false)
        .unwrap_or_else(|e| panic!("parse failed in Lax strictness: {e}"));
    assert_eq!(p.local_part.as_str(p.input), "a.\"b\"");
    assert_eq!(p.domain.as_str(p.input), "example.com");
}

// ── Display name ──

#[test]
fn display_name_angle() {
    let p = parse(
        "John Doe <user@example.com>",
        Strictness::Standard,
        true,
        false,
    )
    .unwrap_or_else(|e| panic!("parse failed: {e}"));
    assert_eq!(p.display_name.map(|s| s.as_str(p.input)), Some("John Doe"));
    assert_eq!(p.local_part.as_str(p.input), "user");
    assert_eq!(p.domain.as_str(p.input), "example.com");
}

#[test]
fn quoted_display_name() {
    let p = parse(
        "\"John Doe\" <user@example.com>",
        Strictness::Standard,
        true,
        false,
    )
    .unwrap_or_else(|e| panic!("parse failed: {e}"));
    assert_eq!(p.display_name.map(|s| s.as_str(p.input)), Some("John Doe"));
}

// ── Domain literal ──

#[test]
fn domain_literal_allowed() {
    let p = parse("user@[192.168.1.1]", Strictness::Standard, false, true)
        .unwrap_or_else(|e| panic!("parse failed: {e}"));
    assert_eq!(p.domain.as_str(p.input), "[192.168.1.1]");
}

#[test]
fn trailing_dot_in_domain_gives_domain_error() {
    // "user@example." — once '.' is consumed, error should be domain-specific.
    let e = parse_err("user@example.");
    assert!(
        matches!(e.kind(), ErrorKind::EmptyDomain),
        "expected EmptyDomain, got {:?}",
        e.kind()
    );
}

#[test]
fn consecutive_dots_in_domain_gives_domain_error() {
    let e = parse_err("user@example..com");
    assert!(
        matches!(e.kind(), ErrorKind::EmptyDomain),
        "expected EmptyDomain, got {:?}",
        e.kind()
    );
}

#[test]
fn strict_rejects_trailing_comment() {
    // RFC 5321 Strict mode must not accept trailing comments/CFWS.
    let e = parse(
        "user@example.com (comment)",
        Strictness::Strict,
        false,
        false,
    )
    .expect_err("Strict mode must reject trailing comment");
    assert!(matches!(e.kind(), ErrorKind::Unexpected { .. }));
}

#[test]
fn strict_rejects_trailing_cfws_in_angle() {
    // Trailing CFWS between domain and '>' in Strict mode.
    let e = parse(
        "<user@example.com (comment)>",
        Strictness::Strict,
        false,
        false,
    )
    .expect_err("Strict mode must reject CFWS before closing angle bracket");
    assert!(matches!(e.kind(), ErrorKind::Unexpected { .. }));
}

#[test]
fn strict_rejects_quoted_local_part() {
    // RFC 5321 Strict mode must reject quoted-string local parts.
    let e = parse("\"quoted\"@example.com", Strictness::Strict, false, false)
        .expect_err("Strict mode must reject quoted-string local part");
    assert_eq!(e.kind(), &ErrorKind::InvalidLocalPartChar { ch: '"' });
}

#[test]
fn strict_rejects_leading_comment() {
    // RFC 5321 Strict mode must reject leading comments/CFWS.
    let e = parse(
        "(comment)user@example.com",
        Strictness::Strict,
        false,
        false,
    )
    .expect_err("Strict mode must reject leading comment");
    // Leading `(` is not valid atext — parser reports the offending char.
    assert_eq!(e.kind(), &ErrorKind::InvalidLocalPartChar { ch: '(' });
}

#[test]
fn standard_accepts_quoted_string_and_comments() {
    // Standard mode (RFC 5322) must accept quoted-string local parts.
    let p = parse("\"quoted\"@example.com", Strictness::Standard, false, false)
        .unwrap_or_else(|e| panic!("Standard must accept quoted-string: {e}"));
    assert_eq!(p.local_part.as_str(p.input), "\"quoted\"");
    assert_eq!(p.domain.as_str(p.input), "example.com");

    // Standard mode must accept trailing comments.
    let p = parse(
        "user@example.com (comment)",
        Strictness::Standard,
        false,
        false,
    )
    .unwrap_or_else(|e| panic!("Standard must accept trailing comment: {e}"));
    assert_eq!(p.local_part.as_str(p.input), "user");
    assert_eq!(p.domain.as_str(p.input), "example.com");
}

#[test]
fn domain_literal_rejected_by_default() {
    let e = parse("user@[192.168.1.1]", Strictness::Standard, false, false)
        .expect_err("expected error");
    assert_eq!(e.kind(), &ErrorKind::InvalidDomainChar { ch: '[' });
}

// ── Regression tests for #13: CFWS stripping in obs-local-part / obs-domain ──

#[test]
fn obs_local_part_cfws_comment_stripped() {
    // obs-local-part with comment between atoms: span must not include CFWS.
    let p = parse_ok_lax("user (comment) . name@example.com");
    assert_eq!(
        p.local_part_str(),
        "user.name",
        "CFWS comment must be stripped from obs-local-part"
    );
}

#[test]
fn obs_local_part_whitespace_stripped() {
    // obs-local-part with plain whitespace between atoms.
    let p = parse_ok_lax("user . name@example.com");
    assert_eq!(
        p.local_part_str(),
        "user.name",
        "whitespace must be stripped from obs-local-part"
    );
}

#[test]
fn obs_domain_cfws_comment_stripped() {
    // obs-domain with comment between labels: span must not include CFWS.
    let p = parse_ok_lax("user@example (comment) . com");
    assert_eq!(
        p.domain_str(),
        "example.com",
        "CFWS comment must be stripped from obs-domain"
    );
}

#[test]
fn obs_domain_whitespace_stripped() {
    // obs-domain with plain whitespace between labels.
    let p = parse_ok_lax("user@example . com");
    assert_eq!(
        p.domain_str(),
        "example.com",
        "whitespace must be stripped from obs-domain"
    );
}

#[test]
fn obs_local_no_cfws_zero_copy() {
    // obs-local-part without CFWS: clean field is None (zero-copy path).
    let p = parse_ok_lax("user.name@example.com");
    assert!(
        p.local_part_clean.is_none(),
        "no CFWS → local_part_clean must be None (zero-copy)"
    );
    assert_eq!(p.local_part_str(), "user.name");
}

#[test]
fn obs_domain_no_cfws_zero_copy() {
    // obs-domain without CFWS: clean field is None (zero-copy path).
    let p = parse_ok_lax("user@example.com");
    assert!(
        p.domain_clean.is_none(),
        "no CFWS → domain_clean must be None (zero-copy)"
    );
    assert_eq!(p.domain_str(), "example.com");
}

#[test]
fn obs_local_part_multiple_comments_stripped() {
    // Multiple CFWS segments between atoms.
    let p = parse_ok_lax("a (c1) . b (c2) . c@example.com");
    assert_eq!(p.local_part_str(), "a.b.c");
}

#[test]
fn obs_leading_comment_accepted_in_bare_addr_spec() {
    // RFC 5322 §3.2.3: local-part dot-atom permits leading [CFWS]
    // (`dot-atom = [CFWS] dot-atom-text [CFWS]`), so a comment before the
    // local-part is valid and stripped from the semantic value. Combined
    // here with obs CFWS between atoms.
    let p = parse(
        "(leading) user . name@example.com",
        Strictness::Lax,
        false,
        false,
    )
    .unwrap_or_else(|e| panic!("leading comment must be accepted: {e}"));
    assert_eq!(p.local_part_str(), "user.name");
    assert_eq!(p.domain_str(), "example.com");
}

#[test]
fn obs_local_cfws_after_dot_no_double_dots() {
    // CFWS only after dot: "user. name" must produce "user.name", not "user..name".
    let p = parse_ok_lax("user. name@example.com");
    assert_eq!(p.local_part_str(), "user.name");
}

#[test]
fn obs_domain_cfws_after_dot_no_double_dots() {
    // CFWS only after dot: "example. com" must produce "example.com", not "example..com".
    let p = parse_ok_lax("user@example. com");
    assert_eq!(p.domain_str(), "example.com");
}

#[test]
fn obs_trailing_cfws_before_at_preserves_zero_copy() {
    // Trailing CFWS before '@' is NOT between atoms — it's excluded from
    // the span by backtracking. Must not trigger allocation or duplicate
    // comment spans.
    let p = parse_ok_lax("user (trailing)@example.com");
    assert!(
        p.local_part_clean.is_none(),
        "trailing CFWS before @ must not trigger allocation"
    );
    assert_eq!(p.local_part_str(), "user");
    assert_eq!(
        p.comments.len(),
        1,
        "backtracked comment must not be duplicated"
    );
}

#[test]
fn obs_trailing_cfws_after_domain_preserves_zero_copy() {
    // Trailing CFWS after domain is NOT between labels — must not allocate
    // or duplicate comment spans.
    let p = parse_ok_lax("user@example.com (trailing)");
    assert!(
        p.domain_clean.is_none(),
        "trailing CFWS after domain must not trigger allocation"
    );
    assert_eq!(p.domain_str(), "example.com");
    assert_eq!(
        p.comments.len(),
        1,
        "backtracked comment must not be duplicated"
    );
}

// ── Leading CFWS before local-part (RFC 5322 dot-atom = [CFWS] ...) ──

#[test]
fn leading_comment_accepted_standard_and_lax() {
    for strictness in [Strictness::Standard, Strictness::Lax] {
        let p = parse("(comment)jane.smith@example.com", strictness, false, false)
            .unwrap_or_else(|e| panic!("{strictness:?}: leading comment must parse: {e}"));
        assert_eq!(p.local_part_str(), "jane.smith");
        assert_eq!(p.domain_str(), "example.com");
    }
}

#[test]
fn leading_comment_in_angle_addr() {
    let p = parse(
        "<(comment)user@example.com>",
        Strictness::Standard,
        false,
        false,
    )
    .unwrap_or_else(|e| panic!("leading comment in angle-addr must parse: {e}"));
    assert_eq!(p.local_part_str(), "user");
}

#[test]
fn strict_still_rejects_leading_comment() {
    let e = parse(
        "(comment)user@example.com",
        Strictness::Strict,
        false,
        false,
    )
    .expect_err("Strict must reject leading comment");
    assert_eq!(e.kind(), &ErrorKind::InvalidLocalPartChar { ch: '(' });
}

#[test]
fn comment_only_local_part_is_empty() {
    let e = parse("(comment)@example.com", Strictness::Lax, false, false)
        .expect_err("comment-only local part must be rejected");
    assert_eq!(e.kind(), &ErrorKind::EmptyLocalPart);
}

// ── CR/LF are not strippable whitespace (header-injection hardening) ──

#[test]
fn rejects_bare_trailing_lf() {
    for input in ["test@iana.org\n", "test@iana.org\r", "test@iana.org\r\n"] {
        assert!(
            parse(input, Strictness::Lax, false, false).is_err(),
            "must reject trailing bare CR/LF: {input:?}"
        );
    }
}

#[test]
fn rejects_bare_leading_cr_lf() {
    for input in ["\rtest@iana.org", "\ntest@iana.org", "\r\ntest@iana.org"] {
        assert!(
            parse(input, Strictness::Lax, false, false).is_err(),
            "must reject leading bare CR/LF: {input:?}"
        );
    }
}

#[test]
fn rejects_bare_cr_in_comment() {
    // A bare CR inside a comment is not valid FWS.
    let e = parse("test@iana.org(\r)", Strictness::Lax, false, false)
        .expect_err("bare CR in comment must be rejected");
    assert!(matches!(e.kind(), ErrorKind::Unexpected { .. }));
}

#[test]
fn comment_may_contain_folding_whitespace() {
    // A comment may fold across lines: CRLF + WSP is valid FWS inside it.
    let p = parse("(a\r\n b)test@iana.org", Strictness::Lax, false, false)
        .unwrap_or_else(|e| panic!("folded comment must parse: {e}"));
    assert_eq!(p.local_part_str(), "test");
}

#[test]
fn accepts_valid_folding_whitespace() {
    // FWS = CRLF followed by WSP — valid leading and trailing.
    let leading = parse(" \r\n test@iana.org", Strictness::Lax, false, false)
        .unwrap_or_else(|e| panic!("leading FWS must parse: {e}"));
    assert_eq!(leading.local_part_str(), "test");

    let trailing = parse("test@iana.org \r\n ", Strictness::Lax, false, false)
        .unwrap_or_else(|e| panic!("trailing FWS must parse: {e}"));
    assert_eq!(trailing.domain_str(), "iana.org");
}

#[test]
fn accepts_trailing_and_leading_space() {
    // Plain leading/trailing spaces are CFWS, accepted in Standard/Lax.
    assert!(parse(" test@iana.org", Strictness::Standard, false, false).is_ok());
    assert!(parse("test@iana.org ", Strictness::Standard, false, false).is_ok());
}

// ── Address-literal validation (RFC 5321 §4.1.3) ──

fn parse_lit(input: &str) -> Result<Parsed<'_>, Error> {
    // Domain literals require allow_domain_literal = true.
    parse(input, Strictness::Lax, false, true)
}

#[test]
fn accepts_valid_ipv4_literal() {
    let p = parse_lit("test@[255.255.255.255]").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(p.domain_str(), "[255.255.255.255]");
}

#[test]
fn accepts_valid_ipv6_literal() {
    for v6 in [
        "test@[IPv6:1111:2222:3333:4444:5555:6666:7777:8888]",
        "test@[IPv6:1111:2222:3333:4444:5555::8888]",
        "test@[IPv6:::]",
        "test@[IPv6:1111:2222:3333:4444::255.255.255.255]",
    ] {
        assert!(parse_lit(v6).is_ok(), "valid IPv6 literal must parse: {v6}");
    }
}

#[test]
fn rejects_malformed_ip_literal() {
    for bad in [
        "test@[255.255.255]",                                  // 3 octets
        "test@[255.255.255.256]",                              // octet > 255
        "test@[IPv6:1111:2222:3333:4444:5555:6666:7777]",      // 7 groups
        "test@[IPv6:1111:2222:3333:4444:5555:6666:7777:888G]", // bad hex
        "test@[IPv6:1::2:]",                                   // trailing colon
        "test@[RFC-5322-domain-literal]",                      // general literal
    ] {
        let e = parse_lit(bad).expect_err(&format!("must reject: {bad}"));
        assert_eq!(
            e.kind(),
            &ErrorKind::InvalidAddressLiteral,
            "wrong error for {bad}"
        );
        assert!(
            e.to_string().contains("address literal"),
            "unexpected Display for {bad}: {e}"
        );
    }
}

#[test]
fn parse_domain_literal_requires_open_bracket() {
    // Defensive contract: the helper errors if called without a leading '['
    // (callers only invoke it after peeking '[').
    let mut parser = Parser::new("nope");
    assert_eq!(
        parse_domain_literal(&mut parser).unwrap_err().kind(),
        &ErrorKind::UnterminatedDomainLiteral
    );
}

#[test]
fn is_qtext_excludes_quote_and_backslash() {
    // '"' and '\\' are never qtext even though '"' is printable ASCII —
    // they are structural delimiters handled before is_qtext is consulted.
    assert!(!is_qtext('"', false));
    assert!(!is_qtext('"', true));
    assert!(!is_qtext('\\', true));
    assert!(is_qtext('a', false));
}

// ── obs-qp / obs-qtext (Lax only) ──

#[test]
fn lax_accepts_obs_qtext_and_obs_qp() {
    // Control chars (obs-NO-WS-CTL) in qtext and after a quoted-pair are
    // valid in Lax mode.
    for input in [
        "\"\u{07}\"@iana.org",   // obs-qtext BEL
        "\"\u{7f}\"@iana.org",   // obs-qtext DEL
        "\"\\\u{00}\"@iana.org", // obs-qp NUL
        "\"\\\u{0a}\"@iana.org", // obs-qp LF
    ] {
        assert!(
            parse(input, Strictness::Lax, false, false).is_ok(),
            "Lax must accept obs-qp/qtext: {input:?}"
        );
    }
}

#[test]
fn standard_rejects_obs_qtext() {
    // Standard (non-obsolete) mode must reject control chars in qtext.
    let e = parse("\"\u{07}\"@iana.org", Strictness::Standard, false, false)
        .expect_err("Standard must reject obs-qtext");
    assert_eq!(e.kind(), &ErrorKind::InvalidLocalPartChar { ch: '\u{07}' });
}

#[test]
fn rejects_quoted_pair_of_non_ascii() {
    // RFC 6531 puts UTF-8 directly in qtext; escaping it via quoted-pair is
    // invalid. Standard reports it directly as an invalid quoted-pair.
    let e = parse(
        "\"test\\\u{a9}\"@iana.org",
        Strictness::Standard,
        false,
        false,
    )
    .expect_err("quoted-pair of non-ASCII must be rejected");
    assert_eq!(e.kind(), &ErrorKind::InvalidQuotedPair);
    // Lax also rejects it (after backtracking the obs-local-part attempt).
    assert!(parse("\"test\\\u{a9}\"@iana.org", Strictness::Lax, false, false).is_err());
}

// ── FWS / recursion / quoted-string edge paths ──

#[test]
fn quoted_string_consumes_consecutive_wsp() {
    // Two spaces in a row exercise the multi-WSP loop in try_eat_fws.
    let p = parse("\"a  b\"@example.com", Strictness::Standard, false, false)
        .unwrap_or_else(|e| panic!("quoted string with double space: {e}"));
    assert_eq!(p.local_part.as_str(p.input), "\"a  b\"");
}

#[test]
fn parse_quoted_string_requires_open_quote() {
    // Defensive contract: errors when not invoked at a '"'.
    let mut parser = Parser::new("x");
    assert_eq!(
        parse_quoted_string(&mut parser, false).unwrap_err().kind(),
        &ErrorKind::UnterminatedQuotedString
    );
}

#[test]
fn deeply_nested_comment_is_rejected() {
    // Comment nesting beyond MAX_RECURSION_DEPTH is rejected (DoS guard).
    let input = format!(
        "{}x{}test@iana.org",
        "(".repeat(MAX_RECURSION_DEPTH + 2),
        ")".repeat(MAX_RECURSION_DEPTH + 2)
    );
    assert!(parse(&input, Strictness::Lax, false, false).is_err());
}

// ── Display-name parsing paths (allow_display_name = true) ──

#[test]
fn quoted_local_part_not_treated_as_display_name() {
    // A quoted string with no following '<' is the local-part, not a
    // display name — try_parse_display_name backtracks.
    let p = parse("\"quoted\"@example.com", Strictness::Standard, true, false)
        .unwrap_or_else(|e| panic!("quoted local with display_name enabled: {e}"));
    assert_eq!(p.display_name, None);
    assert_eq!(p.local_part.as_str(p.input), "\"quoted\"");
}

#[test]
fn malformed_quoted_display_name_backtracks() {
    // An unterminated quoted string in display position backtracks, then
    // fails as a quoted local-part.
    let e = parse(
        "\"unterminated@example.com",
        Strictness::Standard,
        true,
        false,
    )
    .expect_err("unterminated quoted must fail");
    assert_eq!(e.kind(), &ErrorKind::UnterminatedQuotedString);
}

#[test]
fn control_char_aborts_display_name_scan() {
    // A control character aborts the unquoted display-name scan; parsing
    // then falls back to addr-spec and rejects the control char.
    let e = parse("\u{01}user@example.com", Strictness::Standard, true, false)
        .expect_err("control char must be rejected");
    assert_eq!(e.kind(), &ErrorKind::InvalidLocalPartChar { ch: '\u{01}' });
}

#[test]
fn unquoted_text_without_angle_is_not_display_name() {
    // Unquoted text reaching end-of-input with no '<' is not a display
    // name; it is parsed as an addr-spec, which here lacks '@'.
    let e = parse("plainname", Strictness::Standard, true, false)
        .expect_err("bare text without '@' must fail");
    assert_eq!(e.kind(), &ErrorKind::MissingAtSign);
}

#[test]
fn leading_cfws_before_quoted_display_name() {
    // A leading space (CFWS) before a quoted display name must not divert
    // parsing to the unquoted scanner — the display name must be the
    // unquoted "John Doe", not the raw `"John Doe"` with quotes.
    let p = parse(
        " \"John Doe\" <user@example.com>",
        Strictness::Standard,
        true,
        false,
    )
    .unwrap_or_else(|e| panic!("leading CFWS + quoted display name: {e}"));
    assert_eq!(p.display_name.map(|s| s.as_str(p.input)), Some("John Doe"));
    assert_eq!(p.local_part.as_str(p.input), "user");
}

#[test]
fn ipv6_address_literal_tag_is_case_insensitive() {
    // RFC ABNF string literals are case-insensitive, so the `IPv6:` tag may
    // be written in any case.
    for input in [
        "user@[ipv6:::1]",
        "user@[IPV6:2001:db8::1]",
        "user@[IPv6:::1]",
    ] {
        assert!(
            parse(input, Strictness::Lax, false, true).is_ok(),
            "case-insensitive IPv6 tag must parse: {input}"
        );
    }
}
