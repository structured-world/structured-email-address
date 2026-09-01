//! RFC 5321 grammar conformance, pinned against the normative text.
//!
//! The isEmail corpus in `conformance.rs` stays the baseline for a routable
//! mail destination. These cases pin the grammar itself, so a future tightening
//! cannot quietly narrow what the crate accepts without a test naming the
//! section it now contradicts.

use structured_email_address::{Config, EmailAddress, ErrorKind};

/// Read the grammar as written: every `address-literal` alternative.
fn rfc5321() -> Config {
    Config::builder().allow_address_literal_rfc5321().build()
}

/// Read a routable destination: IPv4 and `IPv6:` literals only.
fn routable() -> Config {
    Config::builder().allow_domain_literal().build()
}

fn parses(input: &str, config: &Config) -> bool {
    EmailAddress::parse_with(input, config).is_ok()
}

// ── address-literal alternatives (RFC 5321 §4.1.3) ───────────────────────────
//
//   address-literal = "[" ( IPv4-address-literal /
//                           IPv6-address-literal /
//                           General-address-literal ) "]"

#[test]
fn ipv4_address_literal_is_accepted_by_both_readings() {
    // The first alternative names a routable destination, so it is in scope for
    // the default reading as well as for the grammar.
    assert!(parses("user@[192.168.1.1]", &routable()));
    assert!(parses("user@[192.168.1.1]", &rfc5321()));
}

#[test]
fn ipv6_address_literal_is_accepted_by_both_readings() {
    // The "IPv6:" tag is an ABNF string literal, so it is case-insensitive
    // (RFC 5234 §2.3).
    for input in ["user@[IPv6:2001:db8::1]", "user@[ipv6:::1]"] {
        assert!(parses(input, &routable()), "{input}");
        assert!(parses(input, &rfc5321()), "{input}");
    }
}

#[test]
fn general_address_literal_needs_the_grammar_reading() {
    // The third alternative is a Mailbox by the grammar and not a mail
    // destination, so only the grammar reading admits it. An X.509 rfc822Name
    // may carry one (RFC 5280 §4.2.1.6), and refusing it makes the certificate
    // unreadable rather than merely unroutable.
    assert!(!parses("postmaster@[AS400:QSYS]", &routable()));
    assert!(parses("postmaster@[AS400:QSYS]", &rfc5321()));
}

#[test]
fn general_address_literal_keeps_the_case_of_its_body() {
    // RFC 5321 §2.4 makes domain NAMES case-insensitive and says nothing of the
    // kind about an address-literal. The body is opaque to SMTP and meaningful
    // to the receiving system, so folding it would hand that system a different
    // address.
    let email = EmailAddress::parse_with("postmaster@[AS400:QSYS]", &rfc5321())
        .expect("General-address-literal must parse under the grammar reading");
    assert_eq!(email.domain(), "[AS400:QSYS]");
}

#[test]
fn an_ip_literal_is_canonicalized_to_one_spelling() {
    // Both parts of an IP literal are case-insensitive: the `IPv6:` tag is an
    // ABNF string literal (RFC 5234 §2.3) and IPv6 hex digits carry no case
    // (RFC 4291 §2.2). Two spellings of one address must therefore land on one
    // canonical domain, or equality and hashing split addresses that route to
    // the same host.
    let upper = EmailAddress::parse_with("user@[IPv6:ABCD::1]", &routable())
        .expect("uppercase IPv6 literal must parse");
    let lower = EmailAddress::parse_with("user@[ipv6:abcd::1]", &routable())
        .expect("lowercase IPv6 literal must parse");
    assert_eq!(upper.domain(), lower.domain());
    assert_eq!(upper.domain(), "[ipv6:abcd::1]");
}

#[test]
fn standardized_tag_is_an_ldh_str() {
    //   Standardized-tag = Ldh-str
    //   Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig      (RFC 5321 §4.1.2)
    // Letters, digits and hyphens, ending in a letter or digit.
    let config = rfc5321();
    assert!(
        parses("user@[a-b-1:x]", &config),
        "interior hyphens are Ldh"
    );
    assert!(
        parses("user@[-tag:x]", &config),
        "the ABNF permits a leading -"
    );
    assert!(
        parses("user@[A:x]", &config),
        "a bare Let-dig is a whole Ldh-str"
    );

    assert!(
        !parses("user@[tag-:x]", &config),
        "Ldh-str must end in Let-dig"
    );
    assert!(!parses("user@[:x]", &config), "the tag cannot be empty");
    assert!(!parses("user@[ta_g:x]", &config), "underscore is not Ldh");
}

#[test]
fn dcontent_covers_its_range_and_stops_at_the_edges() {
    //   dcontent = %d33-90 / %d94-126                    (RFC 5321 §4.1.3)
    // Printable ASCII except space, "[", "\", "]" and DEL.
    let config = rfc5321();

    // Both ends of both runs are inside the grammar.
    for body in ["!", "Z", "^", "~"] {
        let input = alloc_input(body);
        assert!(
            parses(&input, &config),
            "dcontent %d{} must parse",
            body_code(body)
        );
    }

    // Immediately outside each run, and the characters the runs skip.
    for body in [" ", "[", "\\", "\u{7f}"] {
        let input = alloc_input(body);
        assert!(!parses(&input, &config), "{input:?} is not dcontent");
    }
}

#[test]
fn general_address_literal_needs_at_least_one_dcontent() {
    //   General-address-literal = Standardized-tag ":" 1*dcontent
    assert!(!parses("user@[TAG:]", &rfc5321()));
}

#[test]
fn the_ipv6_tag_keeps_its_own_alternative() {
    // RFC 5321 §4.1.3 requires a Standardized-tag to be defined by a
    // Standards-Track RFC. IPv6 is, so `[IPv6:...]` stays the IPv6 alternative
    // and is not reread as free dcontent, even under the grammar reading.
    assert!(!parses("user@[IPv6:1::2:]", &rfc5321()));
    assert!(!parses("user@[IPv6:not-an-address]", &rfc5321()));
}

// ── Snum (RFC 5321 §4.1.3) ───────────────────────────────────────────────────
//
//   IPv4-address-literal = Snum 3("." Snum)
//   Snum = 1*3DIGIT ; representing a decimal integer value in the range 0..255

#[test]
fn snum_admits_a_padded_octet_under_the_grammar_reading() {
    // `1*3DIGIT` in range 0..255, with no rule against padding, so `012` is a
    // valid Snum for 12. The no-padding rule belongs to the URI grammar's
    // dec-octet (RFC 3986 §3.2.2), which is not this grammar.
    assert!(parses("user@[012.0.2.1]", &rfc5321()));

    // The routable reading rejects it on purpose: a zero-padded octet is read
    // as octal by some resolvers, and a destination that resolves two ways is
    // not one.
    assert!(!parses("user@[012.0.2.1]", &routable()));
}

#[test]
fn snum_boundaries_hold_at_both_ends() {
    let config = rfc5321();
    assert!(parses("user@[0.0.0.0]", &config));
    assert!(parses("user@[255.255.255.255]", &config));
    assert!(!parses("user@[256.0.2.1]", &config), "256 is out of range");
    assert!(
        !parses("user@[1234.0.2.1]", &config),
        "1*3DIGIT is at most 3"
    );
    assert!(!parses("user@[.0.2.1]", &config), "1*3DIGIT is at least 1");
}

#[test]
fn the_ipv4_tail_of_an_ipv6v4_literal_follows_the_same_snum() {
    //   IPv6v4-comp = [IPv6-hex *3(":" IPv6-hex)] "::"
    //                 [IPv6-hex *3(":" IPv6-hex) ":"] IPv4-address-literal
    // The tail is the same `IPv4-address-literal` as the standalone alternative,
    // so the `Snum` reading has to agree in both places: padding is inside the
    // grammar, and the grammar reading cannot accept `[012.0.2.1]` while
    // refusing the identical octet embedded in an IPv6v4 form.
    assert!(parses("user@[IPv6:::ffff:012.0.2.1]", &rfc5321()));
    assert!(parses("user@[IPv6:::ffff:12.0.2.1]", &rfc5321()));

    // The routable reading keeps refusing padding, in the tail as at the top.
    assert!(!parses("user@[IPv6:::ffff:012.0.2.1]", &routable()));
    assert!(parses("user@[IPv6:::ffff:12.0.2.1]", &routable()));

    // An out-of-range octet is out of the grammar wherever it sits.
    assert!(!parses("user@[IPv6:::ffff:256.0.2.1]", &rfc5321()));
}

#[test]
fn ipv4_address_literal_needs_exactly_four_octets() {
    //   IPv4-address-literal = Snum 3("." Snum)
    let config = rfc5321();
    assert!(!parses("user@[1.2.3]", &config));
    assert!(!parses("user@[1.2.3.4.5]", &config));
}

#[test]
fn snum_is_ascii_digits_only() {
    // 1*3DIGIT is %x30-39, so a sign, a separator or a non-ASCII digit is out.
    let config = rfc5321();
    assert!(!parses("user@[+1.2.3.4]", &config));
    assert!(!parses("user@[1_2.3.4.5]", &config));
    assert!(
        !parses("user@[١٢٣.0.2.1]", &config),
        "Arabic-Indic digits are not DIGIT"
    );
}

// ── Local-part (RFC 5321 §4.1.2) ─────────────────────────────────────────────
//
//   Local-part = Dot-string / Quoted-string
//   qtextSMTP  = %d32-33 / %d35-91 / %d93-126
//   quoted-pairSMTP = %d92 %d32-126

#[test]
fn quoted_local_part_may_hold_an_at_sign() {
    // Inside a Quoted-string the "@" is qtextSMTP (%d64), not the separator.
    let email: EmailAddress = "\"user@name\"@example.com"
        .parse()
        .expect("a quoted local part may contain @");
    assert_eq!(email.local_part(), "user@name");
    assert_eq!(email.domain(), "example.com");
}

#[test]
fn quoted_local_part_admits_a_quoted_pair() {
    //   quoted-pairSMTP = %d92 %d32-126: a backslash before any printable.
    for input in ["\"a\\\"b\"@example.com", "\"a\\\\b\"@example.com"] {
        assert!(
            parses(input, &Config::default()),
            "{input} is a valid quoted-pairSMTP"
        );
    }
}

#[test]
fn qtext_smtp_covers_its_range_and_stops_at_the_edges() {
    //   qtextSMTP = %d32-33 / %d35-91 / %d93-126
    // Everything printable except the bare quote (%d34) and backslash (%d92),
    // both of which must be escaped as a quoted-pair instead.
    let config = Config::default();
    for body in [" ", "!", "#", "[", "]", "~"] {
        let input = alloc_quoted(body);
        assert!(parses(&input, &config), "{input:?} must parse");
    }
    // The two excluded octets cannot simply be dropped into the wrapper: a
    // backslash before any printable is a quoted-pairSMTP, so `"a\b"` is valid
    // and says nothing about %d92. Each needs the construction where it appears
    // bare.
    assert!(
        !parses("\"a\"b\"@example.com", &config),
        "%d34 bare closes the Quoted-string early"
    );
    assert!(
        !parses("\"ab\\\"@example.com", &config),
        "%d92 bare escapes the closing quote, leaving it unterminated"
    );
    assert!(
        parses("\"a\\b\"@example.com", &config),
        "%d92 before a printable is a quoted-pairSMTP, not bare"
    );
}

// ── Size limits (RFC 5321 §4.5.3.1) ──────────────────────────────────────────

#[test]
fn local_part_is_capped_at_64_octets() {
    // §4.5.3.1.1: "The maximum total length of a user name or other local-part
    // is 64 octets."
    let config = Config::default();
    let at_limit = format!("{}@example.com", "a".repeat(64));
    let over = format!("{}@example.com", "a".repeat(65));

    assert!(parses(&at_limit, &config));
    let err = EmailAddress::parse_with(&over, &config).expect_err("65 octets is over the limit");
    assert!(
        matches!(err.kind(), ErrorKind::LocalPartTooLong { len: 65 }),
        "expected LocalPartTooLong, got {:?}",
        err.kind()
    );
}

#[test]
fn an_over_long_domain_is_rejected() {
    // §4.5.3.1.2 caps the domain at 255 octets, but §4.5.3.1.3 caps the whole
    // path at 256 and is what binds first: with a local part of at least one
    // octet the domain can never reach 255 without the total rule firing. This
    // pins the outcome rather than which rule reports it.
    let config = Config::default();
    let domain = format!("{}.com", "a".repeat(60).repeat(4));
    let over = format!("user@{domain}");
    assert!(
        !parses(&over, &config),
        "a 240+ octet domain must be rejected"
    );
}

#[test]
fn a_domain_label_is_capped_at_63_octets() {
    // RFC 1035 §2.3.4, carried into RFC 5321 §4.1.2 sub-domain.
    let config = Config::default();
    assert!(parses(&format!("user@{}.com", "a".repeat(63)), &config));
    assert!(!parses(&format!("user@{}.com", "a".repeat(64)), &config));
}

// ── Domain (RFC 5321 §4.1.2) ─────────────────────────────────────────────────

#[test]
fn a_single_sub_domain_is_a_domain_only_when_asked_for() {
    // RFC 5321 writes `Domain = sub-domain *("." sub-domain)`, so one label is a
    // Domain; RFC 2821 wrote `sub-domain 1*("." sub-domain)` and required two.
    // The decision here: the 2821 reading is the default, because a
    // single-label destination is unroutable outside a local network, and the
    // 5321 reading is one builder call away.
    assert!(!parses("user@localhost", &Config::default()));

    let permissive = Config::builder().allow_single_label_domain().build();
    assert!(parses("user@localhost", &permissive));
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Wrap a dcontent candidate in a General-address-literal.
fn alloc_input(body: &str) -> String {
    format!("user@[TAG:{body}]")
}

/// Wrap a qtextSMTP candidate in a quoted local part.
fn alloc_quoted(body: &str) -> String {
    format!("\"a{body}b\"@example.com")
}

/// Decimal code point of a single-character body, for assertion messages.
fn body_code(body: &str) -> u32 {
    body.chars().next().map_or(0, u32::from)
}
