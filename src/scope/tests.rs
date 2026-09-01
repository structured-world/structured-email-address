use super::*;

use alloc::format;

fn literal(content: &str) -> LiteralScope {
    match classify(&format!("[{content}]")) {
        DomainScope::Literal(scope) => scope,
        other => panic!("expected a literal for '[{content}]', got {other:?}"),
    }
}

// ── Names ──

#[test]
fn a_registrable_name_is_global() {
    assert_eq!(classify("example.com"), DomainScope::Global);
    assert_eq!(classify("mail.example.co.uk"), DomainScope::Global);
}

#[test]
fn a_single_label_is_local() {
    // The name a resolver on this network answers for, and nothing outside it.
    assert_eq!(classify("printer"), DomainScope::Local);
    assert_eq!(classify("localhost"), DomainScope::Local);
}

#[test]
fn the_reserved_names_are_local() {
    for domain in [
        "host.localhost",
        "host.test",
        "host.invalid",
        "host.example",
        "files.local",
        "home.arpa",
        "printer.home.arpa",
        "db.internal",
    ] {
        assert_eq!(
            classify(domain),
            DomainScope::Local,
            "{domain} is reserved for use inside a network"
        );
    }
}

#[test]
fn reserved_names_match_whole_labels_only() {
    // The direction that a substring match would get wrong: each of these ends
    // with the letters of a reserved name without being under it.
    for domain in [
        "notlocal.com",
        "localhost.com",
        "example.com",
        "test.com",
        "internal.com",
        "nothome.arpa",
    ] {
        assert_eq!(
            classify(domain),
            DomainScope::Global,
            "{domain} is not under a reserved name"
        );
    }
}

#[test]
fn a_name_under_no_delegated_suffix_is_local() {
    // With the PSL compiled in this is a name the root zone does not delegate;
    // without it, one whose final label is not TLD-like. Both readings agree
    // that it means something only to the resolver being asked.
    assert_eq!(classify("printer.lan.4"), DomainScope::Local);
}

#[cfg(feature = "psl")]
#[test]
fn an_unknown_tld_is_local_when_the_suffix_list_is_compiled_in() {
    // TLD-like by shape, absent from the root zone. Only the PSL reading can
    // tell the difference, so this case is what the feature buys.
    assert_eq!(classify("host.nonexistenttld"), DomainScope::Local);
    assert_eq!(classify("host.com"), DomainScope::Global);
}

#[test]
fn names_the_dns_never_resolves_are_not_global() {
    // Special-use names whose resolution is defined to happen outside the DNS.
    // `Global` claims the global DNS can resolve the name, and for these it
    // cannot — by the document that reserved them, not by circumstance.
    //
    // `.onion` fails in both feature configurations, not just without the
    // suffix list: the PSL lists `onion`, so asking it returns a known suffix
    // and reports the name as registrable.
    assert_eq!(classify("site.onion"), DomainScope::Local);
    assert_eq!(classify("service.alt"), DomainScope::Local);
}

#[test]
fn is_global_folds_the_name_cases() {
    assert!(classify("example.com").is_global());
    assert!(!classify("files.local").is_global());
    assert!(!classify("printer").is_global());
}

// ── Literals ──

#[test]
fn a_public_ipv4_literal_is_global() {
    assert_eq!(literal("192.0.2.1"), LiteralScope::Ipv4(IpScope::Global));
    assert_eq!(literal("8.8.8.8"), LiteralScope::Ipv4(IpScope::Global));
}

#[test]
fn the_reserved_ipv4_ranges_are_local() {
    for content in [
        "10.0.0.1",        // RFC 1918
        "172.16.0.1",      // RFC 1918, low edge
        "172.31.255.254",  // RFC 1918, high edge
        "192.168.1.5",     // RFC 1918
        "100.64.0.1",      // RFC 6598, low edge
        "100.127.255.254", // RFC 6598, high edge
        "169.254.1.1",     // RFC 3927
        "127.0.0.1",       // RFC 1122 loopback
        "0.0.0.0",         // RFC 1122 "this network"
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv4(IpScope::Local),
            "{content} is reserved for use inside a network"
        );
    }
}

#[test]
fn the_ipv4_addresses_that_never_leave_the_network_are_local() {
    for content in [
        "255.255.255.255", // RFC 919 §7 limited broadcast: never forwarded
        "224.0.0.1",       // RFC 5771 §4 local network control block
        "224.0.0.251",     // the same block, where mDNS lives
        "239.1.2.3",       // RFC 2365 §4 administratively scoped multicast
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv4(IpScope::Local),
            "{content} does not leave the network it is sent on"
        );
    }
}

#[test]
fn the_ipv4_multicast_that_does_leave_the_network_stays_global() {
    // The direction that a whole-224/4 rule would get wrong: multicast is not
    // local by being multicast, only by its assigned scope.
    for content in [
        "224.0.1.1", // internetwork control, forwarded
        "233.1.2.3", // RFC 3180 GLOP, globally assigned
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv4(IpScope::Global),
            "{content} is routable multicast"
        );
    }
}

#[test]
fn ipv6_multicast_is_local_below_global_scope() {
    //   RFC 4291 §2.7: the fourth nibble is the scope, and only 0xE is global.
    for content in [
        "IPv6:ff01::1", // interface-local
        "IPv6:ff02::1", // link-local, the all-nodes address
        "IPv6:ff05::1", // site-local
        "IPv6:ff08::1", // organization-local
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv6(IpScope::Local),
            "{content} is confined to its scope"
        );
    }
    assert_eq!(
        literal("IPv6:ff0e::1"),
        LiteralScope::Ipv6(IpScope::Global),
        "scope 0xE is global multicast"
    );
}

#[test]
fn the_ranges_neighbouring_the_reserved_ipv4_ones_are_global() {
    // The off-by-one direction: each of these sits immediately outside a
    // reserved range, and a mask written one bit wide would swallow it.
    for content in [
        "172.15.255.255", // just below 172.16/12
        "172.32.0.1",     // just above 172.16/12
        "100.63.255.255", // just below 100.64/10
        "100.128.0.1",    // just above 100.64/10
        "169.253.0.1",    // just below 169.254/16
        "169.255.0.1",    // just above 169.254/16
        "11.0.0.1",       // just above 10/8
        "192.169.0.1",    // just above 192.168/16
        "126.0.0.1",      // just below 127/8
        "128.0.0.1",      // just above 127/8
        "1.0.0.1",        // just above 0/8
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv4(IpScope::Global),
            "{content} is outside every reserved range"
        );
    }
}

#[test]
fn a_padded_ipv4_literal_keeps_its_value() {
    // `Snum` allows the padding the URI grammar does not, so this is the same
    // address as 10.0.0.1 and must not read as some other one.
    assert_eq!(
        literal("010.000.000.001"),
        LiteralScope::Ipv4(IpScope::Local)
    );
}

#[test]
fn a_public_ipv6_literal_is_global() {
    assert_eq!(
        literal("IPv6:2001:db8::1"),
        LiteralScope::Ipv6(IpScope::Global)
    );
}

#[test]
fn the_reserved_ipv6_ranges_are_local() {
    for content in [
        "IPv6:fd00::1", // RFC 4193, the fd00::/8 half in general use
        "IPv6:fc00::1", // RFC 4193, low edge of fc00::/7
        "IPv6:fdff::1", // RFC 4193, high edge
        "IPv6:fe80::1", // RFC 4291 link-local, low edge
        "IPv6:febf::1", // RFC 4291 link-local, high edge
        "IPv6:::1",     // RFC 4291 loopback
        "IPv6:::",      // RFC 4291 unspecified
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv6(IpScope::Local),
            "{content} is reserved for use inside a network"
        );
    }
}

#[test]
fn the_ranges_neighbouring_the_reserved_ipv6_ones_are_global() {
    for content in [
        "IPv6:fbff::1", // just below fc00::/7
        "IPv6:fe00::1", // above fc00::/7, below fe80::/10
        "IPv6:fec0::1", // just above fe80::/10
    ] {
        assert_eq!(
            literal(content),
            LiteralScope::Ipv6(IpScope::Global),
            "{content} is outside every reserved range"
        );
    }
}

#[test]
fn an_ipv4_mapped_literal_reports_the_reach_of_the_address_it_holds() {
    // Two spellings of one host: classifying them differently would make the
    // answer depend on how the address was written rather than where it goes.
    assert_eq!(
        literal("IPv6:::ffff:192.168.1.5"),
        LiteralScope::Ipv6(IpScope::Local)
    );
    assert_eq!(
        literal("IPv6:::ffff:192.0.2.1"),
        LiteralScope::Ipv6(IpScope::Global)
    );
}

#[test]
fn an_ipv4_mapped_literal_with_a_padded_tail_is_read_the_same_way() {
    // The depadding path, which `Ipv6Addr` alone refuses.
    assert_eq!(
        literal("IPv6:::ffff:192.168.001.005"),
        LiteralScope::Ipv6(IpScope::Local)
    );
}

#[test]
fn a_general_address_literal_is_neither_family_and_never_global() {
    assert_eq!(literal("AS400:QSYS"), LiteralScope::General);
    assert!(!classify("[AS400:QSYS]").is_global());
}

#[test]
fn is_global_folds_the_literal_cases() {
    assert!(classify("[192.0.2.1]").is_global());
    assert!(!classify("[192.168.1.5]").is_global());
    assert!(classify("[IPv6:2001:db8::1]").is_global());
    assert!(!classify("[IPv6:fd00::1]").is_global());
}
