//! Error types for email address parsing and validation.

use core::fmt;

/// Error returned when parsing or validating an email address fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    position: usize,
}

/// The specific kind of error that occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Input is empty or whitespace-only.
    Empty,
    /// Missing `@` separator.
    MissingAtSign,
    /// Local part is empty (nothing before `@`).
    EmptyLocalPart,
    /// Domain is empty (nothing after `@`).
    EmptyDomain,
    /// Local part exceeds 64 octets (RFC 5321 §4.5.3.1.1).
    LocalPartTooLong { len: usize },
    /// Total address exceeds 254 octets (RFC 5321 §4.5.3.1.3).
    AddressTooLong { len: usize },
    /// Domain label exceeds 63 octets (RFC 1035 §2.3.4).
    DomainLabelTooLong { label: String, len: usize },
    /// Invalid character in local part.
    InvalidLocalPartChar { ch: char },
    /// Invalid character in domain.
    InvalidDomainChar { ch: char },
    /// Domain label starts or ends with hyphen.
    DomainLabelHyphen,
    /// Domain has no dot (single label, not a valid internet domain).
    DomainNoDot,
    /// Unterminated quoted string.
    UnterminatedQuotedString,
    /// Invalid quoted-pair sequence.
    InvalidQuotedPair,
    /// Unterminated comment.
    UnterminatedComment,
    /// Unterminated domain literal `[...]`.
    UnterminatedDomainLiteral,
    /// IDNA encoding failed for domain.
    IdnaError(String),
    /// Domain not in Public Suffix List (when PSL validation enabled).
    UnknownTld(String),
    /// Generic parse failure at position.
    Unexpected { ch: char },
}

impl Error {
    /// Create a new error of the given kind at the given byte position.
    pub(crate) fn new(kind: ErrorKind, position: usize) -> Self {
        Self { kind, position }
    }

    /// The kind of error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Byte offset in the input where the error was detected.
    pub fn position(&self) -> usize {
        self.position
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Empty => write!(f, "empty input"),
            ErrorKind::MissingAtSign => write!(f, "missing '@' separator"),
            ErrorKind::EmptyLocalPart => write!(f, "empty local part"),
            ErrorKind::EmptyDomain => write!(f, "empty domain"),
            ErrorKind::LocalPartTooLong { len } => {
                write!(f, "local part too long: {len} octets (max 64)")
            }
            ErrorKind::AddressTooLong { len } => {
                write!(f, "address too long: {len} octets (max 254)")
            }
            ErrorKind::DomainLabelTooLong { label, len } => {
                write!(f, "domain label '{label}' too long: {len} octets (max 63)")
            }
            ErrorKind::InvalidLocalPartChar { ch } => {
                write!(f, "invalid character in local part: '{ch}'")
            }
            ErrorKind::InvalidDomainChar { ch } => {
                write!(f, "invalid character in domain: '{ch}'")
            }
            ErrorKind::DomainLabelHyphen => {
                write!(f, "domain label starts or ends with hyphen")
            }
            ErrorKind::DomainNoDot => write!(f, "domain has no dot"),
            ErrorKind::UnterminatedQuotedString => write!(f, "unterminated quoted string"),
            ErrorKind::InvalidQuotedPair => write!(f, "invalid quoted-pair escape"),
            ErrorKind::UnterminatedComment => write!(f, "unterminated comment"),
            ErrorKind::UnterminatedDomainLiteral => write!(f, "unterminated domain literal"),
            ErrorKind::IdnaError(msg) => write!(f, "IDNA error: {msg}"),
            ErrorKind::UnknownTld(tld) => write!(f, "unknown TLD: .{tld}"),
            ErrorKind::Unexpected { ch } => {
                write!(
                    f,
                    "unexpected character '{ch}' at position {}",
                    self.position
                )
            }
        }
    }
}

impl std::error::Error for Error {}
