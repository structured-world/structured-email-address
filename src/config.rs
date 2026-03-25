//! Configuration for email address parsing, validation, and normalization.
//!
//! The builder pattern allows fine-grained control over every aspect of
//! email handling — from RFC strictness level to provider-aware normalization.

/// How strictly to validate RFC grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strictness {
    /// RFC 5321 envelope: dot-atom only, no comments, no quoted strings, no obs-*.
    /// Rejects technically valid but practically useless addresses.
    Strict,
    /// RFC 5322 header: full grammar including quoted strings, comments, CFWS.
    /// This is the correct conformant mode.
    #[default]
    Standard,
    /// Standard + obs-local-part, obs-domain for legacy compatibility.
    Lax,
}

/// How to handle dots in the local part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DotPolicy {
    /// Do not strip dots.
    #[default]
    Preserve,
    /// Strip dots only for known providers that ignore them (Gmail, Googlemail).
    GmailOnly,
    /// Always strip dots from local part.
    Always,
}

/// How to handle letter case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CasePolicy {
    /// Lowercase domain only (RFC says local part is case-sensitive, but domain is not).
    #[default]
    Domain,
    /// Lowercase both local part and domain. Most providers are case-insensitive.
    All,
    /// Preserve original case everywhere.
    Preserve,
}

/// How to validate the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainCheck {
    /// No domain validation beyond RFC syntax.
    #[default]
    Syntax,
    /// Validate against Public Suffix List.
    ///
    /// **Requires the `psl` feature.** Falls back to [`Tld`](Self::Tld) check
    /// when the `psl` feature is disabled.
    Psl,
    /// Require that the final label is syntactically TLD-like.
    ///
    /// Checks that the last label is at least two ASCII alphabetic characters
    /// (e.g., `com`, `net`). Does *not* verify against a real TLD list —
    /// use [`Psl`](Self::Psl) for semantic validation.
    Tld,
}

/// Whether to strip +subaddress tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubaddressPolicy {
    /// Keep subaddress in canonical form. Tag is still extracted and accessible.
    #[default]
    Preserve,
    /// Strip subaddress from canonical form. Original still accessible.
    Strip,
}

/// Configuration for email address parsing and normalization.
///
/// # Example
///
/// ```
/// use structured_email_address::Config;
///
/// let config = Config::builder()
///     .strip_subaddress()
///     .dots_gmail_only()
///     .lowercase_all()
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) strictness: Strictness,
    pub(crate) dot_policy: DotPolicy,
    pub(crate) case_policy: CasePolicy,
    pub(crate) domain_check: DomainCheck,
    pub(crate) subaddress: SubaddressPolicy,
    pub(crate) subaddress_separator: char,
    pub(crate) check_confusables: bool,
    pub(crate) allow_domain_literal: bool,
    pub(crate) allow_display_name: bool,
    pub(crate) require_tld_dot: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            strictness: Strictness::Standard,
            dot_policy: DotPolicy::Preserve,
            case_policy: CasePolicy::Domain,
            domain_check: DomainCheck::Syntax,
            subaddress: SubaddressPolicy::Preserve,
            subaddress_separator: '+',
            check_confusables: false,
            allow_domain_literal: false,
            allow_display_name: false,
            require_tld_dot: true,
        }
    }
}

impl Config {
    /// Create a builder with default settings.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder(Config::default())
    }
}

/// Builder for [`Config`].
pub struct ConfigBuilder(Config);

impl ConfigBuilder {
    /// Set RFC strictness level.
    pub fn strictness(mut self, s: Strictness) -> Self {
        self.0.strictness = s;
        self
    }

    /// Strip subaddress from canonical form.
    pub fn strip_subaddress(mut self) -> Self {
        self.0.subaddress = SubaddressPolicy::Strip;
        self
    }

    /// Keep subaddress in canonical form (default).
    pub fn preserve_subaddress(mut self) -> Self {
        self.0.subaddress = SubaddressPolicy::Preserve;
        self
    }

    /// Set the subaddress separator character (default: `+`).
    pub fn subaddress_separator(mut self, sep: char) -> Self {
        self.0.subaddress_separator = sep;
        self
    }

    /// Strip dots only for Gmail/Googlemail.
    pub fn dots_gmail_only(mut self) -> Self {
        self.0.dot_policy = DotPolicy::GmailOnly;
        self
    }

    /// Always strip dots from local part.
    pub fn dots_always_strip(mut self) -> Self {
        self.0.dot_policy = DotPolicy::Always;
        self
    }

    /// Preserve dots (default).
    pub fn dots_preserve(mut self) -> Self {
        self.0.dot_policy = DotPolicy::Preserve;
        self
    }

    /// Lowercase both local part and domain.
    pub fn lowercase_all(mut self) -> Self {
        self.0.case_policy = CasePolicy::All;
        self
    }

    /// Lowercase domain only (default, RFC-correct).
    pub fn lowercase_domain(mut self) -> Self {
        self.0.case_policy = CasePolicy::Domain;
        self
    }

    /// Preserve original case.
    pub fn preserve_case(mut self) -> Self {
        self.0.case_policy = CasePolicy::Preserve;
        self
    }

    /// Validate domain against Public Suffix List (requires `psl` feature).
    pub fn domain_check_psl(mut self) -> Self {
        self.0.domain_check = DomainCheck::Psl;
        self
    }

    /// Validate domain has a recognized TLD.
    pub fn domain_check_tld(mut self) -> Self {
        self.0.domain_check = DomainCheck::Tld;
        self
    }

    /// Enable anti-homoglyph confusable detection.
    pub fn check_confusables(mut self) -> Self {
        self.0.check_confusables = true;
        self
    }

    /// Allow domain literals like `[192.168.1.1]`.
    pub fn allow_domain_literal(mut self) -> Self {
        self.0.allow_domain_literal = true;
        self
    }

    /// Allow display names like `"John Doe" <john@example.com>`.
    pub fn allow_display_name(mut self) -> Self {
        self.0.allow_display_name = true;
        self
    }

    /// Do not require a dot in the domain (allow single-label domains).
    pub fn allow_single_label_domain(mut self) -> Self {
        self.0.require_tld_dot = false;
        self
    }

    /// Build the config.
    pub fn build(self) -> Config {
        self.0
    }
}
