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
    domains: Vec<Box<str>>,
    strip_dots: bool,
    lowercase_local: bool,
    subaddress_sep: Option<char>,
    is_freemail: bool,
}

impl ProviderRule {
    /// Create a rule for the given domains (matched case-insensitively).
    ///
    /// Defaults: no dot stripping, no case folding, `+` subaddress separator,
    /// and `is_freemail = true` (most registered providers are freemail).
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            domains: domains
                .into_iter()
                .map(|d| d.into().to_ascii_lowercase().into_boxed_str())
                .collect(),
            strip_dots: false,
            lowercase_local: false,
            subaddress_sep: Some('+'),
            is_freemail: true,
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

    /// Returns true if `domain` (compared case-insensitively) belongs to this provider.
    pub fn matches(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| domain.eq_ignore_ascii_case(d))
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
    rules: Vec<ProviderRule>,
}

impl ProviderRegistry {
    /// An empty registry.
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// The built-in registry of well-known mail providers.
    ///
    /// Only Gmail/Googlemail ignore dots; every entry folds local-part case and
    /// uses `+` as its subaddress separator. All built-ins are freemail.
    pub fn builtin() -> Self {
        let p = |domains: &[&str]| ProviderRule::new(domains.iter().copied()).lowercase_local(true);
        Self {
            rules: vec![
                p(&["gmail.com", "googlemail.com"]).strip_dots(true),
                p(&["outlook.com", "hotmail.com", "live.com", "msn.com"]),
                p(&["yahoo.com", "yahoo.co.uk", "yahoo.co.jp"]),
                p(&["protonmail.com", "proton.me"]),
                p(&["icloud.com", "me.com", "mac.com"]),
                p(&["yandex.ru", "yandex.com"]),
                p(&["mail.ru"]),
                // Freemail providers without special normalization quirks.
                p(&[
                    "aol.com",
                    "mail.com",
                    "zoho.com",
                    "gmx.com",
                    "gmx.de",
                    "web.de",
                    "tutanota.com",
                    "tuta.io",
                    "fastmail.com",
                ]),
            ],
        }
    }

    /// Add a rule. User-added rules take precedence over earlier ones.
    pub fn add(&mut self, rule: ProviderRule) {
        self.rules.push(rule);
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
    /// the same domain.
    pub fn lookup(&self, domain: &str) -> Option<&ProviderRule> {
        self.rules.iter().rev().find(|r| r.matches(domain))
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests;
