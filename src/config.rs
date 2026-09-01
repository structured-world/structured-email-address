//! Configuration for email address parsing, validation, and normalization.
//!
//! The builder pattern allows fine-grained control over every aspect of
//! email handling — from RFC strictness level to provider-aware normalization.

use crate::provider::{ProviderRegistry, ProviderRule};

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
    /// Preserve original case for local part (domain is always lowercased per RFC 5321).
    Preserve,
}

/// Which `address-literal` spellings the domain may take (RFC 5321 §4.1.3).
///
/// The grammar names three alternatives:
///
/// ```text
/// address-literal = "[" ( IPv4-address-literal /
///                         IPv6-address-literal /
///                         General-address-literal ) "]"
/// ```
///
/// A domain literal is refused unless asked for, so the default is
/// [`Reject`](Self::Reject). Of the two readings a caller can opt into, the
/// destination-oriented one, [`Routable`](Self::Routable), covers the first two
/// alternatives, which are the only ones mail can be delivered to. A reader of
/// an identity rather than a destination needs the third:
/// an X.509 `rfc822Name` is a `Mailbox` as RFC 5321 defines it (RFC 5280
/// §4.2.1.6), and refusing a spelling the grammar names makes the certificate
/// carrying it unreadable rather than merely unroutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressLiteral {
    /// Reject every `[...]` domain literal.
    #[default]
    Reject,
    /// Accept only a literal naming a routable destination: an IPv4 dotted-quad
    /// or an `IPv6:`-tagged IPv6 address.
    ///
    /// Stricter than the grammar in one place, deliberately: RFC 5321 `Snum` is
    /// `1*3DIGIT` in the range 0..=255 with no rule against padding, so
    /// `[012.0.2.1]` is inside the grammar. It is rejected here because a
    /// zero-padded octet is read as octal by some resolvers, and a destination
    /// that resolves two ways is not one. Use [`Rfc5321`](Self::Rfc5321) to read
    /// the grammar as written.
    Routable,
    /// Accept every alternative the grammar names, `General-address-literal`
    /// included, so `postmaster@[AS400:QSYS]` parses.
    ///
    /// ```text
    /// General-address-literal = Standardized-tag ":" 1*dcontent
    /// Standardized-tag        = Ldh-str
    /// dcontent                = %d33-90 / %d94-126
    /// ```
    ///
    /// The `IPv6` tag keeps its own alternative's meaning: RFC 5321 §4.1.3
    /// requires a standardized tag to be defined by a Standards-Track RFC, and
    /// IPv6 is, so `[IPv6:...]` must still hold an IPv6 address and is not
    /// reinterpreted as free `dcontent`.
    Rfc5321,
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
    pub(crate) address_literal: AddressLiteral,
    pub(crate) allow_display_name: bool,
    pub(crate) require_tld_dot: bool,
    /// Whether `Local-part` keeps its `Quoted-string` alternative under
    /// [`Strictness::Strict`]. The other two modes admit it either way.
    pub(crate) quoted_local_part: bool,
    /// When true, a matched provider rule's dot/case/separator override the
    /// global policies for that address.
    pub(crate) provider_aware: bool,
    /// Provider registry: source of truth for [`is_freemail`](crate::EmailAddress::is_freemail)
    /// (always) and provider-aware normalization (when `provider_aware`).
    pub(crate) providers: ProviderRegistry,
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
            address_literal: AddressLiteral::Reject,
            allow_display_name: false,
            require_tld_dot: true,
            quoted_local_part: false,
            provider_aware: false,
            providers: ProviderRegistry::builtin(),
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

    /// Preserve original case for local part (domain is always lowercased per RFC 5321).
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

    /// Allow domain literals that name a routable destination, like
    /// `[192.168.1.1]` or `[IPv6:::1]`.
    ///
    /// See [`AddressLiteral::Routable`] for the one place this reads the RFC
    /// 5321 grammar more strictly than it is written.
    pub fn allow_domain_literal(mut self) -> Self {
        self.0.address_literal = AddressLiteral::Routable;
        self
    }

    /// Allow every `address-literal` RFC 5321 §4.1.3 names, including
    /// `General-address-literal`.
    ///
    /// Use this to read an address out of a document rather than to route mail
    /// to it: `postmaster@[AS400:QSYS]` is a `Mailbox` by the grammar, and an
    /// X.509 `rfc822Name` may hold one (RFC 5280 §4.2.1.6).
    ///
    /// ```
    /// use structured_email_address::{Config, EmailAddress};
    ///
    /// let config = Config::builder().allow_address_literal_rfc5321().build();
    /// let email = EmailAddress::parse_with("postmaster@[AS400:QSYS]", &config).unwrap();
    /// assert_eq!(email.domain(), "[AS400:QSYS]");
    /// ```
    pub fn allow_address_literal_rfc5321(mut self) -> Self {
        self.0.address_literal = AddressLiteral::Rfc5321;
        self
    }

    /// Accept a quoted local part, `"a b"@example.com`.
    ///
    /// ```text
    /// Local-part = Dot-string / Quoted-string
    /// ```
    ///
    /// Under [`Strictness::Strict`] this restores the second alternative (RFC
    /// 5321 §4.1.2), so the pair reads the envelope grammar as written, which
    /// is what a consumer validating an identity rather than routing mail
    /// needs: an X.509 `rfc822Name` is a `Mailbox` (RFC 5280 §4.2.1.6), and a
    /// quoted local part is one. [`Standard`](Strictness::Standard) and
    /// [`Lax`](Strictness::Lax) already read the wider RFC 5322 grammar, which
    /// includes the quoted form, so this changes nothing there.
    ///
    /// The alphabet is the envelope one, `qtextSMTP` and `quoted-pairSMTP`:
    /// printable ASCII and space, with the quote and the backslash reachable
    /// only through a backslash, plus UTF-8 (RFC 6531 §3.3). It is narrower
    /// than the RFC 5322 quoted string, so this cannot smuggle the header
    /// grammar into the envelope one — a tab, a folded line or a control
    /// character is still refused.
    ///
    /// ```
    /// use structured_email_address::{Config, EmailAddress, Strictness};
    ///
    /// let config = Config::builder()
    ///     .strictness(Strictness::Strict)
    ///     .allow_quoted_local_part()
    ///     .build();
    ///
    /// let email = EmailAddress::parse_with("\"a b\"@example.com", &config).unwrap();
    /// assert_eq!(email.local_part(), "a b");
    /// assert_eq!(email.canonical(), "\"a b\"@example.com");
    ///
    /// // A comment is header syntax, and Strict still refuses it.
    /// assert!(EmailAddress::parse_with("a(c)@example.com", &config).is_err());
    /// ```
    pub fn allow_quoted_local_part(mut self) -> Self {
        self.0.quoted_local_part = true;
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

    /// Syntax-only domain check (default). Resets from `Psl`/`Tld` back to syntax.
    pub fn domain_check_syntax(mut self) -> Self {
        self.0.domain_check = DomainCheck::Syntax;
        self
    }

    /// Enable provider-aware normalization.
    ///
    /// When enabled, an address whose domain matches a registered
    /// [`ProviderRule`] is normalized by that provider's rule (dot stripping,
    /// case folding, subaddress separator) instead of the global policies.
    /// Addresses with no matching provider still use the global policies.
    ///
    /// Provider lookups for [`is_freemail`](crate::EmailAddress::is_freemail)
    /// work regardless of this setting — it only gates normalization.
    pub fn provider_aware(mut self) -> Self {
        self.0.provider_aware = true;
        self
    }

    /// Register a custom [`ProviderRule`], extending the built-in registry.
    ///
    /// User rules take precedence over built-ins for the same domain, so this
    /// can also redefine a built-in provider. Affects [`is_freemail`](crate::EmailAddress::is_freemail)
    /// always, and normalization when [`provider_aware`](Self::provider_aware) is set.
    pub fn add_provider(mut self, rule: ProviderRule) -> Self {
        self.0.providers.add(rule);
        self
    }

    /// Replace the entire provider registry (e.g. start from
    /// [`ProviderRegistry::empty`](crate::ProviderRegistry::empty)).
    pub fn providers(mut self, registry: ProviderRegistry) -> Self {
        self.0.providers = registry;
        self
    }

    /// Build the config.
    pub fn build(self) -> Config {
        self.0
    }
}
