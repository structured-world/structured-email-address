use super::*;

/// Helper: look up a rule, panicking with a clear message if absent (no unwrap/expect).
fn rule<'a>(reg: &'a ProviderRegistry, domain: &str) -> &'a ProviderRule {
    match reg.lookup(domain) {
        Some(r) => r,
        None => panic!("expected a provider rule for {domain}"),
    }
}

#[test]
fn builtin_gmail_rule() {
    let reg = ProviderRegistry::builtin();
    let g = rule(&reg, "gmail.com");
    assert!(g.strips_dots(), "gmail ignores dots");
    assert!(g.folds_case());
    assert_eq!(g.separator(), Some('+'));
    assert!(g.is_freemail());
    // Alias resolves to the same rule.
    assert!(rule(&reg, "googlemail.com").strips_dots());
}

#[test]
fn builtin_lookup_is_case_insensitive() {
    let reg = ProviderRegistry::builtin();
    assert!(reg.lookup("GMAIL.COM").is_some());
    assert!(reg.lookup("Yahoo.Com").is_some());
}

#[test]
fn only_gmail_strips_dots_among_builtins() {
    let reg = ProviderRegistry::builtin();
    for d in [
        "outlook.com",
        "yahoo.com",
        "proton.me",
        "icloud.com",
        "mail.ru",
    ] {
        assert!(!rule(&reg, d).strips_dots(), "{d} must not strip dots");
    }
}

#[test]
fn builtin_freemail_coverage() {
    // Every domain the legacy hardcoded list recognized must still be freemail.
    let reg = ProviderRegistry::builtin();
    for d in [
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.co.jp",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "aol.com",
        "protonmail.com",
        "proton.me",
        "icloud.com",
        "me.com",
        "mac.com",
        "mail.com",
        "zoho.com",
        "yandex.ru",
        "yandex.com",
        "mail.ru",
        "gmx.com",
        "gmx.de",
        "web.de",
        "tutanota.com",
        "tuta.io",
        "fastmail.com",
    ] {
        assert!(
            reg.lookup(d).is_some_and(ProviderRule::is_freemail),
            "{d} must be a known freemail provider"
        );
    }
}

#[test]
fn unknown_domain_has_no_rule() {
    let reg = ProviderRegistry::builtin();
    assert!(reg.lookup("example.com").is_none());
    assert!(reg.lookup("company.org").is_none());
}

#[test]
fn user_rule_takes_precedence_over_builtin() {
    // Re-define gmail to NOT strip dots; the user rule must win.
    let reg = ProviderRegistry::builtin().with(
        ProviderRule::new(["gmail.com"])
            .strip_dots(false)
            .lowercase_local(true),
    );
    assert!(!rule(&reg, "gmail.com").strips_dots());
}

#[test]
fn custom_provider_added() {
    let reg = ProviderRegistry::builtin().with(
        ProviderRule::new(["corp.example"])
            .strip_dots(true)
            .subaddress_separator(Some('-'))
            .freemail(false),
    );
    let r = rule(&reg, "corp.example");
    assert!(r.strips_dots());
    assert_eq!(r.separator(), Some('-'));
    assert!(!r.is_freemail());
}

#[test]
fn custom_rule_is_not_freemail_by_default() {
    // A normalization-only custom rule must not be reported as freemail.
    let reg = ProviderRegistry::builtin().with(ProviderRule::new(["mail.corp.example"]));
    assert!(!rule(&reg, "mail.corp.example").is_freemail());
}

#[test]
fn idn_rule_matches_unicode_and_punycode() {
    // A rule registered in Unicode matches both spellings, and one registered in
    // punycode matches the Unicode spelling — IDNA canonicalization is consistent.
    let uni = ProviderRegistry::empty().with(ProviderRule::new(["münchen.de"]).freemail(true));
    assert!(uni.lookup("münchen.de").is_some());
    assert!(uni.lookup("xn--mnchen-3ya.de").is_some());

    let puny =
        ProviderRegistry::empty().with(ProviderRule::new(["xn--mnchen-3ya.de"]).freemail(true));
    assert!(puny.lookup("münchen.de").is_some());
    assert!(puny.lookup("xn--mnchen-3ya.de").is_some());
}

#[test]
fn idn_rule_matches_decomposed_unicode_nfc() {
    // IDNA canonicalization applies Unicode NFC, so a rule registered with the
    // composed form (ü = U+00FC) still matches a lookup using the decomposed
    // form (u + combining diaeresis U+0308) — the two are the same domain.
    let reg =
        ProviderRegistry::empty().with(ProviderRule::new(["m\u{00fc}nchen.de"]).freemail(true));
    assert!(
        reg.lookup("mu\u{0308}nchen.de").is_some(),
        "decomposed spelling matches the composed rule via NFC"
    );
}

#[test]
fn idn_rule_rejects_confusable_lookalike() {
    // A visually confusable domain using Cyrillic 'а' (U+0430) instead of Latin
    // 'a' (U+0061) is a DIFFERENT domain: it canonicalizes to a different label
    // and must not match the Latin rule (no homoglyph collision in lookup).
    let reg = ProviderRegistry::empty().with(ProviderRule::new(["gmail.com"]).freemail(true));
    assert!(
        reg.lookup("gm\u{0430}il.com").is_none(),
        "Cyrillic lookalike must not match the Latin gmail.com rule"
    );
    // Sanity: the genuine Latin domain still matches.
    assert!(reg.lookup("gmail.com").is_some());
}

#[test]
fn rule_no_subaddressing() {
    let r = ProviderRule::new(["x.example"]).subaddress_separator(None);
    assert_eq!(r.separator(), None);
}

#[test]
fn empty_registry_matches_nothing() {
    assert!(ProviderRegistry::empty().lookup("gmail.com").is_none());
}

#[test]
fn matches_canonicalizes_before_comparing() {
    // The public matcher takes a domain in any spelling and canonicalizes it,
    // so a rule registered in Unicode answers for the punycode form and back.
    let rule = ProviderRule::new(["münchen.de"]);
    assert!(rule.matches("münchen.de"));
    assert!(rule.matches("xn--mnchen-3ya.de"));
    assert!(rule.matches("MÜNCHEN.DE"));
    assert!(!rule.matches("muenchen.de"));
}

#[test]
fn a_domain_idna_cannot_encode_falls_back_to_ascii_lowercasing() {
    // Registry input is arbitrary: a caller can register something IDNA refuses
    // outright, such as a label that claims to be punycode and decodes to
    // nothing. Matching must still answer rather than panic, so canonicalization
    // falls back to ASCII lowercasing and the rule matches itself.
    let rule = ProviderRule::new(["XN--"]);
    assert!(rule.matches("xn--"), "the fallback must be self-consistent");
    assert!(rule.matches("XN--"));
    assert!(!rule.matches("example.com"));
}

#[test]
fn the_default_registry_is_the_built_in_one() {
    let default = ProviderRegistry::default();
    assert!(
        default
            .lookup("gmail.com")
            .is_some_and(super::ProviderRule::strips_dots),
        "Default must carry the built-ins"
    );
}
