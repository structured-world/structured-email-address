//! SMTP identity syntax must be checkable without constructing normalized strings.

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};
use structured_email_address::is_smtp_mailbox;

// Only this integration-test binary observes allocator calls. Production
// remains safe Rust; forwarding an allocator requires Rust's unsafe trait.
struct Observed;
std::thread_local! {
    // Const TLS has no initialization allocation and no destructor. Only the
    // calling test thread is observed, even under the standard parallel harness.
    static OBSERVING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn observe() {
    // Allocator calls can also happen after thread-local teardown. In that
    // case no test interval is active; an allocator must not unwind.
    let _ = OBSERVING.try_with(|active| {
        if active.get() {
            ALLOCATIONS.with(|count| count.set(count.get() + 1));
        }
    });
}

unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe();
        // SAFETY: the unchanged layout comes from the caller's allocator contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: every allocation above was obtained from System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe();
        // SAFETY: preserve the caller's pointer/layout/size contract and allocator.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Observed = Observed;

#[test]
fn smtp_syntax_success_and_refusal_allocate_nothing() {
    // Fixture creation and test diagnostics happen outside the observed
    // interval, so hidden temporary
    // strings as well as retained allocations cause a failure.
    let too_long = "a".repeat(1_000_000);
    let long_label = format!("a@{}", "a".repeat(64));
    let config = structured_email_address::Config::builder()
        .strictness(structured_email_address::Strictness::Strict)
        .allow_quoted_local_part()
        .allow_address_literal_rfc5321()
        .allow_single_label_domain()
        .build();
    OBSERVING.set(true);
    let owned = structured_email_address::EmailAddress::parse_with("user@example.com", &config);
    OBSERVING.set(false);
    assert!(owned.is_ok());
    assert!(
        ALLOCATIONS.get() > 0,
        "the observer must see the old owned pipeline"
    );
    drop(owned);
    let mut answers = [false; 10];
    ALLOCATIONS.set(0);
    OBSERVING.set(true);
    for (answer, input) in answers.iter_mut().zip([
        "user@example.com",
        "\"a b\"@localhost",
        "user@[012.0.2.1]",
        "user@[IPv6:::ffff:012.0.2.1]",
        "user@[AS400:QSYS]",
        "user(comment)@example.com",
        "user@[IPv6:garbage]",
        "üser@example.com",
        &long_label,
        &too_long,
    ]) {
        *answer = is_smtp_mailbox(input);
    }
    OBSERVING.set(false);
    assert_eq!(ALLOCATIONS.get(), 0);
    assert_eq!(
        answers,
        [
            true, true, true, true, true, false, false, false, false, false
        ]
    );
}

#[test]
fn smtp_syntax_accepts_quoted_atoms_hosts_and_literals() {
    // These are envelope Mailbox forms, including valid but rarely routable forms.
    for input in [
        "user+tag@example.com",
        "user@localhost",
        "user@123",
        "\"a b\"@example.com",
        "\"a@b\"@example.com",
        "\"\"@example.com",
        "\"a\\\"b\"@example.com",
        "user@[012.0.2.1]",
        "user@[IPv6:::1]",
        "user@[ipv6:::ffff:012.0.2.1]",
        "user@[AS400:QSYS]",
    ] {
        assert!(is_smtp_mailbox(input), "{input:?}");
    }
}

#[test]
fn smtp_syntax_refuses_header_forms_non_ascii_and_malformed_literals() {
    // Header syntax and SMTPUTF8 are separate contracts; neither may widen ASCII Mailbox.
    for input in [
        "",
        "@example.com",
        "user@",
        "Alice <user@example.com>",
        "<user@example.com>",
        " user@example.com",
        "user@example.com ",
        "user(comment)@example.com",
        "user@exam_ple.com",
        "user@-example.com",
        "user@example-.com",
        "a..b@example.com",
        ".a@example.com",
        "a.@example.com",
        "\"a\tb\"@example.com",
        "\"a\\\tb\"@example.com",
        "user\r\n@example.com",
        "üser@example.com",
        "user@bücher.de",
        "user@[256.0.0.1]",
        "user@[IPv6:garbage]",
        "user@[host]",
        "user@[TAG:]",
    ] {
        assert!(!is_smtp_mailbox(input), "{input:?}");
    }
}

#[test]
fn smtp_syntax_checks_octet_and_label_boundaries() {
    // Bound checks precede traversal of oversized input; exact limits remain accepted.
    assert!(is_smtp_mailbox(&format!("{}@example.com", "a".repeat(64))));
    assert!(!is_smtp_mailbox(&format!("{}@example.com", "a".repeat(65))));
    assert!(is_smtp_mailbox(&format!("a@{}", "a".repeat(63))));
    assert!(!is_smtp_mailbox(&format!("a@{}", "a".repeat(64))));
    let host = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(61));
    let exact = format!("{}@{host}", "a".repeat(64));
    assert_eq!(exact.len(), 254);
    assert!(is_smtp_mailbox(&exact));
    assert!(!is_smtp_mailbox(&format!("{exact}c")));
}

#[test]
fn smtp_literal_compression_obeys_the_selected_rfc5321_grammar() {
    // RFC 5321 §4.1.3 compresses at least two groups. Erratum 4315 is held
    // for document update, not a verified replacement of this grammar.
    let config = structured_email_address::Config::builder()
        .strictness(structured_email_address::Strictness::Strict)
        .allow_quoted_local_part()
        .allow_address_literal_rfc5321()
        .allow_single_label_domain()
        .build();
    for input in ["a@[IPv6:1:2:3:4:5:6::7]", "a@[IPv6:1:2:3:4:5::192.0.2.1]"] {
        assert!(!is_smtp_mailbox(input), "{input}");
        assert!(structured_email_address::EmailAddress::parse_with(input, &config).is_err());
    }
    for input in ["a@[IPv6:1:2:3:4:5::6]", "a@[IPv6:1:2:3:4::192.0.2.1]"] {
        assert!(is_smtp_mailbox(input), "{input}");
        assert!(structured_email_address::EmailAddress::parse_with(input, &config).is_ok());
    }
}

#[test]
fn smtp_syntax_agrees_with_the_existing_strict_grammar_on_ascii_mutations() {
    // These ASCII mutations avoid intentional syntax-only differences such as
    // an empty quoted local part. Compare against the full owned pipeline;
    // no copied second grammar decides the result.
    let config = structured_email_address::Config::builder()
        .strictness(structured_email_address::Strictness::Strict)
        .allow_quoted_local_part()
        .allow_address_literal_rfc5321()
        .allow_single_label_domain()
        .build();
    for template in [
        "ab@cd.ef",
        "\"a b\"@cd",
        "a@[012.0.2.1]",
        "a@[IPv6:::1]",
        "a@[TAG:X]",
    ] {
        let mut bytes = template.as_bytes().to_vec();
        for at in 0..bytes.len() {
            let original = bytes[at];
            for byte in 0_u8..=127 {
                bytes[at] = byte;
                let Ok(input) = core::str::from_utf8(&bytes) else {
                    panic!("ASCII mutation produced invalid UTF-8");
                };
                let owned =
                    structured_email_address::EmailAddress::parse_with(input, &config).is_ok();
                assert_eq!(is_smtp_mailbox(input), owned, "{input:?}");
            }
            bytes[at] = original;
        }
    }
}
