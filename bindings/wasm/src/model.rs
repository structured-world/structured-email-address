//! The plain objects the JavaScript API exchanges, and their conversion to and
//! from the crate's types.
//!
//! Kept apart from the `wasm_bindgen` exports so the native parity harness can
//! serialize exactly what the module returns, without a JavaScript engine.

use serde::{Deserialize, Serialize};
use structured_email_address::{
    Config, DomainScope, EmailAddress, Error, ErrorKind, IpScope, LiteralScope, ProviderRegistry,
    ProviderRule, Strictness,
};

/// A fully resolved configuration: every field present, as the JavaScript side
/// produces after validating the caller's options and filling the defaults.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsConfig {
    pub strictness: JsStrictness,
    pub dot_policy: JsDotPolicy,
    pub case_policy: JsCasePolicy,
    pub domain_check: JsDomainCheck,
    pub subaddress: JsSubaddress,
    pub subaddress_separator: String,
    pub check_confusables: bool,
    pub address_literal: JsAddressLiteral,
    pub allow_display_name: bool,
    pub allow_single_label_domain: bool,
    pub allow_quoted_local_part: bool,
    pub provider_aware: bool,
    pub builtin_providers: bool,
    pub providers: Vec<JsProviderRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsStrictness {
    Strict,
    Standard,
    Lax,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsDotPolicy {
    Preserve,
    GmailOnly,
    Always,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsCasePolicy {
    Domain,
    All,
    Preserve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsDomainCheck {
    Syntax,
    Psl,
    Tld,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsSubaddress {
    Preserve,
    Strip,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JsAddressLiteral {
    Reject,
    Routable,
    Rfc5321,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsProviderRule {
    pub domains: Vec<String>,
    pub strip_dots: bool,
    pub lowercase_local: bool,
    /// One character, or `None` for a provider without subaddressing.
    pub subaddress_separator: Option<String>,
    pub freemail: bool,
}

/// The single character a separator option must hold.
fn one_char(value: &str, what: &str) -> Result<char, String> {
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), None) => Ok(ch),
        _ => Err(format!(
            "{what} must be exactly one character, got {value:?}"
        )),
    }
}

impl TryFrom<JsConfig> for Config {
    type Error = String;

    fn try_from(js: JsConfig) -> Result<Self, String> {
        let mut builder = Config::builder()
            .strictness(match js.strictness {
                JsStrictness::Strict => Strictness::Strict,
                JsStrictness::Standard => Strictness::Standard,
                JsStrictness::Lax => Strictness::Lax,
            })
            .subaddress_separator(one_char(&js.subaddress_separator, "subaddressSeparator")?);
        builder = match js.dot_policy {
            JsDotPolicy::Preserve => builder.dots_preserve(),
            JsDotPolicy::GmailOnly => builder.dots_gmail_only(),
            JsDotPolicy::Always => builder.dots_always_strip(),
        };
        builder = match js.case_policy {
            JsCasePolicy::Domain => builder.lowercase_domain(),
            JsCasePolicy::All => builder.lowercase_all(),
            JsCasePolicy::Preserve => builder.preserve_case(),
        };
        builder = match js.domain_check {
            JsDomainCheck::Syntax => builder.domain_check_syntax(),
            JsDomainCheck::Psl => builder.domain_check_psl(),
            JsDomainCheck::Tld => builder.domain_check_tld(),
        };
        builder = match js.subaddress {
            JsSubaddress::Preserve => builder.preserve_subaddress(),
            JsSubaddress::Strip => builder.strip_subaddress(),
        };
        builder = match js.address_literal {
            // The builder starts from the default, which rejects literals.
            JsAddressLiteral::Reject => builder,
            JsAddressLiteral::Routable => builder.allow_domain_literal(),
            JsAddressLiteral::Rfc5321 => builder.allow_address_literal_rfc5321(),
        };
        if js.check_confusables {
            builder = builder.check_confusables();
        }
        if js.allow_display_name {
            builder = builder.allow_display_name();
        }
        if js.allow_single_label_domain {
            builder = builder.allow_single_label_domain();
        }
        if js.allow_quoted_local_part {
            builder = builder.allow_quoted_local_part();
        }
        if js.provider_aware {
            builder = builder.provider_aware();
        }
        if !js.builtin_providers {
            builder = builder.providers(ProviderRegistry::empty());
        }
        for rule in js.providers {
            let separator = match rule.subaddress_separator {
                Some(sep) => Some(one_char(&sep, "provider subaddressSeparator")?),
                None => None,
            };
            builder = builder.add_provider(
                ProviderRule::new(rule.domains)
                    .strip_dots(rule.strip_dots)
                    .lowercase_local(rule.lowercase_local)
                    .subaddress_separator(separator)
                    .freemail(rule.freemail),
            );
        }
        Ok(builder.build())
    }
}

/// A parsed address as JavaScript sees it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsEmail {
    pub original: String,
    pub local_part: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub domain: String,
    pub domain_unicode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skeleton: Option<String>,
    pub freemail: bool,
    pub canonical: String,
    /// The `Display` form, with the display name when there is one.
    pub formatted: String,
    pub domain_scope: JsScope,
}

impl From<&EmailAddress> for JsEmail {
    fn from(email: &EmailAddress) -> Self {
        Self {
            original: email.original().to_owned(),
            local_part: email.local_part().to_owned(),
            tag: email.tag().map(str::to_owned),
            domain: email.domain().to_owned(),
            domain_unicode: email.domain_unicode().to_owned(),
            display_name: email.display_name().map(str::to_owned),
            skeleton: email.skeleton().map(str::to_owned),
            freemail: email.is_freemail(),
            canonical: email.canonical(),
            formatted: email.to_string(),
            domain_scope: email.domain_scope().into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum JsScope {
    Global,
    Local,
    Literal { literal: JsLiteral },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum JsLiteral {
    Ipv4 { ip: JsIp },
    Ipv6 { ip: JsIp },
    General,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JsIp {
    Global,
    Local,
}

impl From<IpScope> for JsIp {
    fn from(scope: IpScope) -> Self {
        match scope {
            IpScope::Global => Self::Global,
            IpScope::Local => Self::Local,
        }
    }
}

impl From<DomainScope> for JsScope {
    fn from(scope: DomainScope) -> Self {
        match scope {
            DomainScope::Global => Self::Global,
            DomainScope::Local => Self::Local,
            DomainScope::Literal(literal) => Self::Literal {
                literal: match literal {
                    LiteralScope::Ipv4(ip) => JsLiteral::Ipv4 { ip: ip.into() },
                    LiteralScope::Ipv6(ip) => JsLiteral::Ipv6 { ip: ip.into() },
                    LiteralScope::General => JsLiteral::General,
                },
            },
        }
    }
}

/// A parse failure. The message is composed on the JavaScript side from the
/// kind and position, so both backends word it the same way.
#[derive(Debug, Serialize)]
pub struct JsError {
    pub kind: JsErrorKind,
    /// UTF-16 code-unit offset into the input, the unit JavaScript indexes by.
    pub position: usize,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum JsErrorKind {
    Empty,
    MissingAtSign,
    EmptyLocalPart,
    EmptyDomain,
    LocalPartTooLong { len: usize },
    AddressTooLong { len: usize },
    DomainLabelTooLong { label: String, len: usize },
    InvalidLocalPartChar { ch: String },
    InvalidDomainChar { ch: String },
    DomainLabelHyphen,
    DomainNoDot,
    UnterminatedQuotedString,
    InvalidQuotedPair,
    UnterminatedComment,
    UnterminatedDomainLiteral,
    InvalidAddressLiteral,
    IdnaError { message: String },
    UnknownTld { tld: String },
    Unexpected { ch: String },
}

impl From<&ErrorKind> for JsErrorKind {
    fn from(kind: &ErrorKind) -> Self {
        match kind {
            ErrorKind::Empty => Self::Empty,
            ErrorKind::MissingAtSign => Self::MissingAtSign,
            ErrorKind::EmptyLocalPart => Self::EmptyLocalPart,
            ErrorKind::EmptyDomain => Self::EmptyDomain,
            ErrorKind::LocalPartTooLong { len } => Self::LocalPartTooLong { len: *len },
            ErrorKind::AddressTooLong { len } => Self::AddressTooLong { len: *len },
            ErrorKind::DomainLabelTooLong { label, len } => Self::DomainLabelTooLong {
                label: label.clone(),
                len: *len,
            },
            ErrorKind::InvalidLocalPartChar { ch } => {
                Self::InvalidLocalPartChar { ch: ch.to_string() }
            }
            ErrorKind::InvalidDomainChar { ch } => Self::InvalidDomainChar { ch: ch.to_string() },
            ErrorKind::DomainLabelHyphen => Self::DomainLabelHyphen,
            ErrorKind::DomainNoDot => Self::DomainNoDot,
            ErrorKind::UnterminatedQuotedString => Self::UnterminatedQuotedString,
            ErrorKind::InvalidQuotedPair => Self::InvalidQuotedPair,
            ErrorKind::UnterminatedComment => Self::UnterminatedComment,
            ErrorKind::UnterminatedDomainLiteral => Self::UnterminatedDomainLiteral,
            ErrorKind::InvalidAddressLiteral => Self::InvalidAddressLiteral,
            ErrorKind::IdnaError(message) => Self::IdnaError {
                message: message.clone(),
            },
            ErrorKind::UnknownTld(tld) => Self::UnknownTld { tld: tld.clone() },
            ErrorKind::Unexpected { ch } => Self::Unexpected { ch: ch.to_string() },
        }
    }
}

impl JsError {
    fn new(error: &Error, input: &str) -> Self {
        Self {
            kind: error.kind().into(),
            position: utf16_offset(input, error.position()),
        }
    }
}

/// Convert a byte offset into the UTF-16 offset of the same character.
///
/// The parser only reports offsets on character boundaries; one that is not
/// would be a parser bug, and is clamped to the whole input rather than
/// panicking inside the module.
fn utf16_offset(input: &str, byte: usize) -> usize {
    input
        .get(..byte)
        .unwrap_or(input)
        .chars()
        .map(char::len_utf16)
        .sum()
}

/// The outcome of one parse: exactly one of `value` and `error` is present.
#[derive(Debug, Serialize)]
pub struct JsOutcome {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<JsEmail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsError>,
}

/// Parse one input against an already built configuration.
pub fn parse(input: &str, config: &Config) -> JsOutcome {
    match EmailAddress::parse_with(input, config) {
        Ok(email) => JsOutcome {
            ok: true,
            value: Some((&email).into()),
            error: None,
        },
        Err(error) => JsOutcome {
            ok: false,
            value: None,
            error: Some(JsError::new(&error, input)),
        },
    }
}
