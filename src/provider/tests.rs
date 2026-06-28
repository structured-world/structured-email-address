use super::*;

#[test]
fn builtin_gmail_rule() {
    let reg = ProviderRegistry::builtin();
    let g = reg.lookup("gmail.com").expect("gmail is a known provider");
    assert!(g.strips_dots(), "gmail ignores dots");
    assert!(g.folds_case());
    assert_eq!(g.separator(), Some('+'));
    assert!(g.is_freemail());
    // Alias resolves to the same rule.
    assert!(reg.lookup("googlemail.com").unwrap().strips_dots());
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
        assert!(
            !reg.lookup(d).unwrap().strips_dots(),
            "{d} must not strip dots"
        );
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
    assert!(!reg.lookup("gmail.com").unwrap().strips_dots());
}

#[test]
fn custom_provider_added() {
    let reg = ProviderRegistry::builtin().with(
        ProviderRule::new(["corp.example"])
            .strip_dots(true)
            .subaddress_separator(Some('-'))
            .freemail(false),
    );
    let r = reg.lookup("corp.example").expect("custom provider matches");
    assert!(r.strips_dots());
    assert_eq!(r.separator(), Some('-'));
    assert!(!r.is_freemail());
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
