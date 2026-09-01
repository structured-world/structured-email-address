//! Whether a domain names something the global DNS can resolve, or something
//! that means anything only inside a network.
//!
//! This is not a grammar question, which is why it sits beside the parse rather
//! than inside it: `admin@printer`, `postmaster@files.local`, `a@[192.168.1.5]`
//! and `a@example.com` are all well formed, and what separates them is reach.
//! No verdict here changes what parses.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::parser;

/// How far a domain reaches.
///
/// Obtained from [`EmailAddress::domain_scope`](crate::EmailAddress::domain_scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainScope {
    /// A name the global DNS can resolve.
    ///
    /// With the `psl` feature this is the stronger reading, a name under a
    /// published public suffix; without it, the weaker one, a final label that
    /// is TLD-like. Either way, a name reserved by the documents listed on
    /// [`Local`](Self::Local) is not one of these.
    Global,
    /// A name reserved for use inside a network, or a single label, which has
    /// no meaning outside the resolver that is asked.
    ///
    /// The reserved names, each with the document reserving it:
    ///
    /// | Name | Reserved by |
    /// |---|---|
    /// | `.localhost` | RFC 6761 §6.3 |
    /// | `.test` | RFC 6761 §6.2 |
    /// | `.invalid` | RFC 6761 §6.4 |
    /// | `.example` | RFC 6761 §6.5 |
    /// | `.local` | RFC 6762 §3 |
    /// | `home.arpa` | RFC 8375 §2 |
    /// | `.internal` | ICANN Board resolution 2024.07.29.05 |
    ///
    /// A name whose final label is not TLD-like, or which is under no published
    /// public suffix, lands here too: it is a name only the resolver being
    /// asked can answer for.
    Local,
    /// An address literal, which names a host directly rather than through the
    /// DNS.
    Literal(LiteralScope),
}

impl DomainScope {
    /// Whether the domain names something reachable from the public internet.
    ///
    /// True for [`Global`](Self::Global) and for a literal holding an address
    /// outside the reserved ranges. A `General-address-literal` is never one of
    /// these: its body is meaningful only to the system receiving it.
    pub fn is_global(&self) -> bool {
        match self {
            Self::Global => true,
            Self::Local => false,
            Self::Literal(literal) => literal.is_global(),
        }
    }
}

/// Which address literal, and how far it reaches (RFC 5321 §4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LiteralScope {
    /// `IPv4-address-literal`, as in `[192.0.2.1]`.
    Ipv4(IpScope),
    /// `IPv6-address-literal`, as in `[IPv6:2001:db8::1]`.
    Ipv6(IpScope),
    /// `General-address-literal`, as in `[AS400:QSYS]`: a tagged address whose
    /// body SMTP does not interpret and which is meaningful only to the system
    /// receiving it.
    General,
}

impl LiteralScope {
    /// Whether the literal names an address reachable from the public internet.
    pub fn is_global(&self) -> bool {
        matches!(
            self,
            Self::Ipv4(IpScope::Global) | Self::Ipv6(IpScope::Global)
        )
    }
}

/// How far an IP address reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpScope {
    /// An address outside every range listed on [`Local`](Self::Local).
    ///
    /// Reserved ranges that are neither private nor host-scoped are not
    /// separated out: `192.0.2.1` is documentation space (RFC 5737) and reads
    /// as `Global` here, because the question this answers is whether the
    /// address was set aside for use inside a network, not whether some route
    /// to it exists today.
    Global,
    /// An address that is meaningful only inside a network, or only on the host
    /// that is asked:
    ///
    /// | Range | Reserved by |
    /// |---|---|
    /// | `10/8`, `172.16/12`, `192.168/16` | RFC 1918 §3 |
    /// | `100.64/10` | RFC 6598 §7 |
    /// | `169.254/16` | RFC 3927 §2.1 |
    /// | `127/8`, `0/8` | RFC 1122 §3.2.1.3 |
    /// | `fc00::/7` | RFC 4193 §3 |
    /// | `fe80::/10` | RFC 4291 §2.5.6 |
    /// | `::1`, `::` | RFC 4291 §2.5.3, §2.5.2 |
    Local,
}

/// Names reserved for use inside a network, matched on whole labels.
///
/// Small, fixed, and standards-defined, which is the argument for keeping them
/// here rather than in each consumer: see [`DomainScope::Local`] for the
/// document behind each one.
const RESERVED: &[&str] = &[
    "localhost",
    "test",
    "invalid",
    "example",
    "local",
    "home.arpa",
    "internal",
];

/// Classify a canonical domain: the bracketed form for an address literal, and
/// otherwise the ASCII, lowercased hostname that
/// [`EmailAddress::domain`](crate::EmailAddress::domain) returns.
pub(crate) fn classify(domain: &str) -> DomainScope {
    if let Some(content) = domain.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return DomainScope::Literal(literal_scope(content));
    }
    // A single label names whatever the resolver being asked decides it names,
    // which is the definition of local. It reaches here only when the caller
    // opted into single-label domains; the default still refuses them outright.
    if !domain.contains('.') || is_reserved(domain) || !is_globally_named(domain) {
        return DomainScope::Local;
    }
    DomainScope::Global
}

fn is_reserved(domain: &str) -> bool {
    RESERVED.iter().any(|name| is_within(domain, name))
}

/// Whether `domain` is `name` or a name under it.
///
/// Matched on whole labels, so `notlocal.com` is not under `local` and
/// `nothome.arpa` is not under `home.arpa`.
fn is_within(domain: &str, name: &str) -> bool {
    match domain.strip_suffix(name) {
        Some("") => true,
        Some(prefix) => prefix.ends_with('.'),
        None => false,
    }
}

/// Whether the name is one the global DNS can be expected to resolve.
///
/// With the `psl` feature this asks the Public Suffix List, which is the
/// question worth asking: a name under a published suffix is a name someone can
/// register and the root zone delegates. Without it the crate has no list to
/// consult, so it falls back to the same syntactic reading
/// [`DomainCheck::Tld`](crate::DomainCheck::Tld) uses — weaker, but an answer
/// rather than a compile error for a no-std consumer.
#[cfg(feature = "psl")]
fn is_globally_named(domain: &str) -> bool {
    structured_public_domains::is_known_suffix(domain)
}

#[cfg(not(feature = "psl"))]
fn is_globally_named(domain: &str) -> bool {
    crate::validate::has_tld_like_suffix(domain)
}

fn literal_scope(content: &str) -> LiteralScope {
    // The padded form second: it is the rarer spelling and the plain parse is
    // the cheaper test. An `IPv6:` tag that satisfies neither cannot come from
    // a parsed address — the parser refuses to reread it as free `dcontent`
    // (RFC 5321 §4.1.3) — so it falls to the residual arm rather than being
    // reported as an IPv6 address nobody could name.
    if let Some(addr) = parser::ipv6_address_literal(content)
        .or_else(|| parser::ipv6_address_literal_with_padded_tail(content))
    {
        return LiteralScope::Ipv6(ipv6_scope(addr));
    }
    if let Some(addr) = parser::ipv4_address_literal(content) {
        return LiteralScope::Ipv4(ipv4_scope(addr));
    }
    LiteralScope::General
}

fn ipv4_scope(addr: Ipv4Addr) -> IpScope {
    let [a, b, ..] = addr.octets();
    let local = match (a, b) {
        // RFC 1918 §3: private-use.
        (10, _) | (192, 168) => true,
        (172, 16..=31) => true,
        // RFC 6598 §7: shared address space, 100.64.0.0/10.
        (100, 64..=127) => true,
        // RFC 3927 §2.1: link-local, 169.254.0.0/16.
        (169, 254) => true,
        // RFC 1122 §3.2.1.3: loopback (127/8) and "this network" (0/8). Neither
        // is private use in the RFC 1918 sense, and neither leaves the host
        // being asked, so calling either one global would be a false statement
        // to whoever is reading the address.
        (127 | 0, _) => true,
        _ => false,
    };
    if local {
        IpScope::Local
    } else {
        IpScope::Global
    }
}

fn ipv6_scope(addr: Ipv6Addr) -> IpScope {
    // RFC 4291 §2.5.5.2: an IPv4-mapped address holds an IPv4 address, and its
    // reach is that address's reach. Without this, `[IPv6:::ffff:192.168.1.5]`
    // and `[192.168.1.5]` — the same host, two spellings — would be classified
    // opposite ways.
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return ipv4_scope(mapped);
    }
    let leading = addr.segments()[0];
    let local = addr.is_loopback()                  // RFC 4291 §2.5.3: ::1
        || addr.is_unspecified()                    // RFC 4291 §2.5.2: ::
        || leading & 0xfe00 == 0xfc00               // RFC 4193 §3: fc00::/7
        || leading & 0xffc0 == 0xfe80; // RFC 4291 §2.5.6: fe80::/10
    if local {
        IpScope::Local
    } else {
        IpScope::Global
    }
}

#[cfg(test)]
mod tests;
