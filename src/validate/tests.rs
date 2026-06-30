use super::*;

#[test]
fn tld_valid() {
    assert!(validate_tld("example.com", 0).is_ok());
    assert!(validate_tld("example.co.uk", 0).is_ok());
    assert!(validate_tld("example.xn--p1ai", 0).is_ok()); // .рф in punycode
}

#[test]
fn tld_invalid() {
    assert!(validate_tld("example.x", 0).is_err()); // single char
    assert!(validate_tld("example.123", 0).is_err()); // numeric
}

// ── Full validate() tests ──

#[test]
fn rejects_local_part_too_long() {
    let long_local = "a".repeat(65);
    let input = format!("{long_local}@example.com");
    let result: Result<crate::EmailAddress, _> = input.parse();
    assert!(matches!(
        result.unwrap_err().kind(),
        crate::ErrorKind::LocalPartTooLong { .. }
    ));
}

#[test]
fn rejects_address_too_long() {
    let long_domain = format!("{}.com", "a".repeat(250));
    let input = format!("u@{long_domain}");
    let result: Result<crate::EmailAddress, _> = input.parse();
    let kind = result.unwrap_err().kind().clone();
    assert!(
        matches!(
            kind,
            crate::ErrorKind::AddressTooLong { .. }
                | crate::ErrorKind::DomainLabelTooLong { .. }
                | crate::ErrorKind::IdnaError(_)
        ),
        "expected length or IDNA error, got {kind:?}"
    );
}

#[test]
fn rejects_domain_label_too_long() {
    let long_label = "a".repeat(64);
    let input = format!("user@{long_label}.com");
    let result: Result<crate::EmailAddress, _> = input.parse();
    let kind = result.unwrap_err().kind().clone();
    assert!(
        matches!(
            kind,
            crate::ErrorKind::DomainLabelTooLong { .. } | crate::ErrorKind::IdnaError(_)
        ),
        "expected label-too-long or IDNA error, got {kind:?}"
    );
}

#[test]
fn domain_literal_skips_label_check() {
    let config = crate::Config::builder()
        .allow_domain_literal()
        .allow_single_label_domain()
        .build();
    let result = crate::EmailAddress::parse_with("user@[192.168.1.1]", &config);
    assert!(result.is_ok());
}

// ── PSL validation (structured-public-domains backend) ──

#[cfg(feature = "psl")]
#[test]
fn psl_accepts_known_suffix() {
    // A domain whose public suffix is in the PSL passes domain_check_psl.
    let config = crate::Config::builder().domain_check_psl().build();
    let result = crate::EmailAddress::parse_with("user@example.com", &config);
    assert!(result.is_ok(), "known suffix must pass: {result:?}");
}

#[cfg(feature = "psl")]
#[test]
fn psl_rejects_unknown_suffix() {
    // A made-up TLD matches only the PSL `*` default rule (is_known == false),
    // so PSL validation rejects it with UnknownTld.
    let config = crate::Config::builder().domain_check_psl().build();
    // Single matches! over the Result keeps the test free of unwrap/expect
    // and avoids an uncovered panic arm on the happy path.
    let result = crate::EmailAddress::parse_with("user@example.invalidtldxyz", &config);
    assert!(matches!(
        result.as_ref().map_err(|e| e.kind()),
        Err(crate::ErrorKind::UnknownTld(_))
    ));
}
