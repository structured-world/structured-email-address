//! Provider-aware normalization rules.
//!
//! Different mail providers treat the local part differently: Gmail ignores
//! dots, most freemail providers fold case, subaddress separators vary. A
//! [`ProviderRegistry`] maps domains to [`ProviderRule`]s so normalization can
//! be provider-aware, and applications can register their own providers.
//!
//! The registry is also the source of truth for [`EmailAddress::is_freemail`],
//! independent of whether provider-aware normalization is enabled.
//!
//! [`EmailAddress::is_freemail`]: crate::EmailAddress::is_freemail

use alloc::borrow::Cow;
use alloc::string::String;

/// Normalization rule for one mail provider (a set of equivalent domains).
///
/// Construct with [`ProviderRule::new`] and refine with the builder-style
/// setters. Fields are private so the rule can gain options without a breaking
/// change.
///
/// # Example
///
/// ```
/// use structured_email_address::ProviderRule;
///
/// // A corporate provider that ignores dots and folds case, tag separator '+'.
/// let rule = ProviderRule::new(["mail.example.com"])
///     .strip_dots(true)
///     .lowercase_local(true)
///     .freemail(false);
/// assert!(rule.matches("MAIL.EXAMPLE.COM"));
/// ```
#[derive(Debug, Clone)]
pub struct ProviderRule {
    /// Borrowed for the built-in rules, which are static data, and owned for a
    /// rule a caller builds. Keeping both in one type lets the built-in registry
    /// be a `static` rather than something initialized at first use.
    domains: Cow<'static, [Cow<'static, str>]>,
    strip_dots: bool,
    lowercase_local: bool,
    subaddress_sep: Option<char>,
    is_freemail: bool,
}

impl ProviderRule {
    /// Create a rule for the given domains.
    ///
    /// Domains are stored in their IDNA-ASCII (punycode) canonical form so a
    /// rule registered as `münchen.de` and one as `xn--mnchen-3ya.de` are
    /// equivalent, and matching agrees with the canonical domain used elsewhere.
    ///
    /// Defaults: no dot stripping, no case folding, `+` subaddress separator,
    /// and `is_freemail = false` (a custom rule is treated as a private domain
    /// unless you opt in with [`freemail(true)`](Self::freemail)).
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            domains: Cow::Owned(
                domains
                    .into_iter()
                    .map(|d| Cow::Owned(canonical_domain(&d.into())))
                    .collect(),
            ),
            strip_dots: false,
            lowercase_local: false,
            subaddress_sep: Some('+'),
            is_freemail: false,
        }
    }

    /// Set whether dots in the local part are insignificant (e.g. Gmail).
    #[must_use]
    pub fn strip_dots(mut self, yes: bool) -> Self {
        self.strip_dots = yes;
        self
    }

    /// Set whether the local part is case-insensitive (folded to lowercase).
    #[must_use]
    pub fn lowercase_local(mut self, yes: bool) -> Self {
        self.lowercase_local = yes;
        self
    }

    /// Set the subaddress separator, or `None` if the provider has no
    /// subaddressing.
    #[must_use]
    pub fn subaddress_separator(mut self, sep: Option<char>) -> Self {
        self.subaddress_sep = sep;
        self
    }

    /// Set whether this provider is a free webmail provider.
    #[must_use]
    pub fn freemail(mut self, yes: bool) -> Self {
        self.is_freemail = yes;
        self
    }

    /// Returns true if `domain` belongs to this provider.
    ///
    /// The domain is canonicalized to IDNA-ASCII before comparison, so Unicode
    /// and punycode spellings of the same domain match.
    pub fn matches(&self, domain: &str) -> bool {
        self.matches_canonical(&canonical_domain(domain))
    }

    /// Match against a domain already in canonical (IDNA-ASCII) form.
    fn matches_canonical(&self, canonical: &str) -> bool {
        self.domains.iter().any(|d| &**d == canonical)
    }

    /// Whether the local part's dots are insignificant.
    pub fn strips_dots(&self) -> bool {
        self.strip_dots
    }

    /// Whether the local part is case-insensitive.
    pub fn folds_case(&self) -> bool {
        self.lowercase_local
    }

    /// The provider's subaddress separator, if any.
    pub fn separator(&self) -> Option<char> {
        self.subaddress_sep
    }

    /// Whether this is a free webmail provider.
    pub fn is_freemail(&self) -> bool {
        self.is_freemail
    }
}

/// A set of [`ProviderRule`]s with domain lookup.
///
/// [`builtin`](Self::builtin) seeds the well-known providers; applications can
/// extend it with [`add`](Self::add). User-added rules take precedence over
/// built-ins, so a custom rule can redefine a built-in provider.
#[derive(Debug, Clone)]
pub struct ProviderRegistry {
    rules: Cow<'static, [ProviderRule]>,
}

/// Spell a built-in domain list, which is static data.
macro_rules! domains {
    ($($d:literal),+ $(,)?) => {
        &[$(Cow::Borrowed($d)),+]
    };
}

/// One built-in provider. Every built-in folds local-part case, uses `+` as its
/// subaddress separator and is freemail; only the dot policy varies.
///
/// The domains skip [`canonical_domain`] because they are already written in
/// canonical form: lowercase ASCII with no IDN label to punycode.
const fn builtin(domains: &'static [Cow<'static, str>], strip_dots: bool) -> ProviderRule {
    ProviderRule {
        domains: Cow::Borrowed(domains),
        strip_dots,
        lowercase_local: true,
        subaddress_sep: Some('+'),
        is_freemail: true,
    }
}

// The built-in registry is static data, so it is a `static` and not something
// built at first use. That costs no allocation, no lazy-initialization branch
// and, unlike a `OnceLock`/`OnceBox`, no pointer-width atomic: bare-metal
// targets without a compare-and-swap (thumbv6m, riscv32i) can build the crate.
// `builtin()` clones it and the GmailOnly dot-policy borrows it, and cloning a
// borrowed Cow copies nothing.
static BUILTIN: ProviderRegistry = ProviderRegistry {
    rules: Cow::Borrowed(&[
        builtin(domains!["gmail.com", "googlemail.com"], true),
        builtin(
            domains!["outlook.com", "hotmail.com", "live.com", "msn.com"],
            false,
        ),
        builtin(domains!["yahoo.com", "yahoo.co.uk", "yahoo.co.jp"], false),
        builtin(domains!["protonmail.com", "proton.me"], false),
        builtin(domains!["icloud.com", "me.com", "mac.com"], false),
        builtin(domains!["yandex.ru", "yandex.com"], false),
        builtin(domains!["mail.ru"], false),
        // Freemail providers without special normalization quirks.
        builtin(
            domains![
                "aol.com",
                "mail.com",
                "zoho.com",
                "gmx.com",
                "gmx.de",
                "web.de",
                "tutanota.com",
                "tuta.io",
                "fastmail.com",
            ],
            false,
        ),
    ]),
};

/// Borrow the process-wide built-in registry without allocating.
pub(crate) fn builtin_ref() -> &'static ProviderRegistry {
    &BUILTIN
}

impl ProviderRegistry {
    /// An empty registry.
    pub fn empty() -> Self {
        Self {
            rules: Cow::Borrowed(&[]),
        }
    }

    /// The built-in registry of well-known mail providers.
    ///
    /// Only Gmail/Googlemail ignore dots; every entry folds local-part case and
    /// uses `+` as its subaddress separator. All built-ins are freemail.
    ///
    /// Returns an owned clone of a process-wide shared registry, so the rule set
    /// is constructed (and its domains IDNA-canonicalized) only once.
    pub fn builtin() -> Self {
        builtin_ref().clone()
    }

    /// Add a rule. User-added rules take precedence over earlier ones.
    /// Adding to a registry still borrowing the built-ins copies them once,
    /// here, rather than on every `builtin()` call.
    pub fn add(&mut self, rule: ProviderRule) {
        self.rules.to_mut().push(rule);
    }

    /// Builder-style [`add`](Self::add).
    #[must_use]
    pub fn with(mut self, rule: ProviderRule) -> Self {
        self.add(rule);
        self
    }

    /// Look up the rule for a domain, or `None` if no provider matches.
    ///
    /// Most-recently-added rules win, so a custom rule overrides a built-in for
    /// the same domain. The domain is canonicalized to IDNA-ASCII once, so
    /// Unicode and punycode spellings resolve to the same rule.
    pub fn lookup(&self, domain: &str) -> Option<&ProviderRule> {
        let canonical = canonical_domain(domain);
        self.rules
            .iter()
            .rev()
            .find(|r| r.matches_canonical(&canonical))
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

/// Canonicalize a domain to its IDNA-ASCII (punycode) form, lowercased.
///
/// Falls back to ASCII lowercasing if the input is not a valid domain, so
/// matching never panics on arbitrary registry input.
fn canonical_domain(domain: &str) -> String {
    idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests;
