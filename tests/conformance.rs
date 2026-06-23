//! RFC conformance test against the isEmail test suite
//! ([dominicsayers/isemail](https://github.com/dominicsayers/isemail), v3.05).
//!
//! isEmail assigns every address a *category* on a severity ladder:
//!
//! ```text
//! VALID < DNSWARN < RFC5321 < CFWS < DEPREC < RFC5322 < ERR
//! ```
//!
//! We map each rung onto our [`Strictness`] model. The conformance run uses the
//! most-permissive *valid* configuration (Lax + domain literals + single-label
//! domains) and asserts that it accepts everything up to and including DEPREC
//! (structurally valid, possibly obsolete syntax) and rejects RFC5322 and ERR:
//!
//! - **RFC5322** category = valid only under the loosest reading: over-length
//!   addresses, malformed IP literals (`[IPv6:1::2:]`), and non-IP general
//!   domain literals (`[RFC-5322-domain-literal]`). A practical validator
//!   rejects these, so we do too.
//! - **ERR** = unparseable.
//!
//! Any mismatch must be listed in [`KNOWN_DIVERGENCES`] with a reason, otherwise
//! the test fails — this catches regressions while documenting the handful of
//! intentional or in-flight differences.

use std::collections::BTreeMap;

use structured_email_address::{Config, EmailAddress, Strictness};

const SUITE: &str = include_str!("isemail_tests.xml");

/// Highest ladder rank our Lax-permissive parse is expected to accept.
/// DEPREC (4) and below = accept; RFC5322 (5) and ERR (6) = reject.
const ACCEPT_MAX_RANK: u8 = 4;

/// Categories the issue's acceptance criterion gates on (≥98% pass rate).
const TARGET_CATEGORIES: &[&str] = &[
    "ISEMAIL_VALID_CATEGORY",
    "ISEMAIL_RFC5321",
    "ISEMAIL_RFC5322",
];

/// Cases where our result intentionally differs from the isEmail expectation,
/// each with a justification. Anything not listed here that diverges fails the
/// test as a regression.
///
/// Currently empty: we match all 164 cases of the v3.05 suite under the
/// Lax-permissive mapping. Add an entry here (with a reason) only for a
/// deliberate, documented divergence.
const KNOWN_DIVERGENCES: &[(u32, &str)] = &[];

/// Severity rank of an isEmail category (lower = more valid).
fn rank(category: &str) -> u8 {
    match category {
        "ISEMAIL_VALID_CATEGORY" => 0,
        "ISEMAIL_DNSWARN" => 1,
        "ISEMAIL_RFC5321" => 2,
        "ISEMAIL_CFWS" => 3,
        "ISEMAIL_DEPREC" => 4,
        "ISEMAIL_RFC5322" => 5,
        "ISEMAIL_ERR" => 6,
        other => panic!("unknown isEmail category: {other}"),
    }
}

/// isEmail encodes control characters as the Unicode "control picture" glyphs
/// (U+2400 + ASCII position) so they survive in XML. Map them back to the real
/// control characters before feeding the address to the parser.
fn decode_controls(s: &str) -> String {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            match cp {
                0x2400..=0x241F => char::from_u32(cp - 0x2400).unwrap_or(c),
                0x2420 => ' ',
                0x2421 => '\u{7f}',
                _ => c,
            }
        })
        .collect()
}

fn child_text<'a>(node: &roxmltree::Node<'a, '_>, tag: &str) -> &'a str {
    node.children()
        .find(|n| n.has_tag_name(tag))
        .and_then(|n| n.text())
        .unwrap_or("")
}

#[test]
fn isemail_conformance() {
    let cfg = Config::builder()
        .strictness(Strictness::Lax)
        .allow_domain_literal()
        .allow_single_label_domain()
        .build();

    let doc = roxmltree::Document::parse(SUITE)
        .unwrap_or_else(|e| panic!("isemail_tests.xml must parse: {e}"));

    // (pass, total) per category.
    let mut per_cat: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    let mut divergences: Vec<(u32, String, String, bool, Option<String>)> = Vec::new();

    for node in doc.descendants().filter(|n| n.has_tag_name("test")) {
        let id: u32 = node
            .attribute("id")
            .unwrap_or_else(|| panic!("test must have id"))
            .parse()
            .unwrap_or_else(|e| panic!("id must be numeric: {e}"));
        let address = decode_controls(child_text(&node, "address"));
        let category = child_text(&node, "category");
        assert!(!category.is_empty(), "#{id} missing category");

        let expect_accept = rank(category) <= ACCEPT_MAX_RANK;
        let result = EmailAddress::parse_with(&address, &cfg);
        let got_accept = result.is_ok();

        let entry = per_cat.entry(category).or_default();
        entry.1 += 1;
        if got_accept == expect_accept {
            entry.0 += 1;
        } else {
            let err = result.err().map(|e| e.to_string());
            divergences.push((id, address, category.to_string(), expect_accept, err));
        }
    }

    // Per-category report.
    eprintln!("\nisEmail conformance (Lax-permissive config):");
    for (cat, (pass, total)) in &per_cat {
        eprintln!("  {cat:<24} {pass:>3}/{total:<3}");
    }

    // Classify divergences against the allowlist.
    let mut unexpected = Vec::new();
    if !divergences.is_empty() {
        eprintln!("\ndivergences:");
    }
    for (id, addr, cat, expect_accept, err) in &divergences {
        let reason = KNOWN_DIVERGENCES
            .iter()
            .find(|(kid, _)| kid == id)
            .map(|(_, r)| *r);
        eprintln!(
            "  #{id} [{cat}] expected={} got={} addr={addr:?}{} :: {}",
            if *expect_accept { "accept" } else { "reject" },
            if err.is_some() { "reject" } else { "accept" },
            err.as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default(),
            reason.unwrap_or("UNEXPECTED — regression"),
        );
        if reason.is_none() {
            unexpected.push(*id);
        }
    }

    assert!(
        unexpected.is_empty(),
        "unexpected conformance divergences (not in KNOWN_DIVERGENCES): {unexpected:?}"
    );

    // Acceptance gate: ≥98% on VALID + RFC5321 + RFC5322.
    let (mut pass, mut total) = (0u32, 0u32);
    for cat in TARGET_CATEGORIES {
        let (p, t) = per_cat.get(*cat).copied().unwrap_or((0, 0));
        pass += p;
        total += t;
    }
    let rate = f64::from(pass) / f64::from(total);
    eprintln!("\ntarget categories: {pass}/{total} = {:.1}%", rate * 100.0);
    assert!(
        rate >= 0.98,
        "target pass rate {:.1}% < 98% ({pass}/{total})",
        rate * 100.0
    );
}
