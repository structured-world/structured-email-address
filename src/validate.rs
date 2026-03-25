//! Post-parse validation: length limits, domain checks, TLD validation.

use crate::config::{Config, DomainCheck};
use crate::error::{Error, ErrorKind};
use crate::normalize::Normalized;
use crate::parser::Parsed;

/// Maximum local-part length in octets (RFC 5321 §4.5.3.1.1).
const MAX_LOCAL_PART_LEN: usize = 64;

/// Maximum total address length in octets (RFC 5321 §4.5.3.1.3).
/// This is the addr-spec (without display name), so local + "@" + domain.
const MAX_ADDRESS_LEN: usize = 254;

/// Maximum domain label length in octets (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Validate a parsed and normalized email address.
pub(crate) fn validate(
    parsed: &Parsed<'_>,
    normalized: &Normalized,
    config: &Config,
) -> Result<(), Error> {
    let domain = &normalized.domain;

    // Length limits apply to the RAW addr-spec (RFC 5321 §4.5.3.1),
    // not the normalized form (which may be shorter after tag/dot stripping).
    let raw_local = parsed.local_part.as_str(parsed.input);
    let raw_domain = parsed.domain.as_str(parsed.input);

    // Length: local part (max 64 octets).
    if raw_local.len() > MAX_LOCAL_PART_LEN {
        return Err(Error::new(
            ErrorKind::LocalPartTooLong {
                len: raw_local.len(),
            },
            parsed.local_part.start,
        ));
    }

    // Length: total address (max 254 octets).
    let total = raw_local.len() + 1 + raw_domain.len();
    if total > MAX_ADDRESS_LEN {
        return Err(Error::new(
            ErrorKind::AddressTooLong { len: total },
            parsed.local_part.start,
        ));
    }

    // Domain literals like [192.168.1.1] get special handling below.
    let is_domain_literal = raw_domain.starts_with('[');

    // Domain must have at least one dot (unless configured otherwise).
    if config.require_tld_dot && !domain.contains('.') && !is_domain_literal {
        return Err(Error::new(ErrorKind::DomainNoDot, parsed.domain.start));
    }
    if !is_domain_literal {
        // Domain label length check only applies to hostnames, not domain literals
        // like [192.168.1.1] where splitting on '.' produces invalid labels.
        for label in domain.split('.') {
            if label.len() > MAX_LABEL_LEN {
                return Err(Error::new(
                    ErrorKind::DomainLabelTooLong {
                        label: label.to_string(),
                        len: label.len(),
                    },
                    parsed.domain.start,
                ));
            }
        }

        match config.domain_check {
            DomainCheck::Syntax => {}
            DomainCheck::Tld => validate_tld(domain, parsed.domain.start)?,
            DomainCheck::Psl => validate_psl(domain, parsed.domain.start)?,
        }
    }

    Ok(())
}

/// Basic TLD validation: check the last label is at least 2 chars and all-alpha.
fn validate_tld(domain: &str, pos: usize) -> Result<(), Error> {
    let tld = domain.rsplit('.').next().unwrap_or(domain);
    // Punycode TLDs start with xn--
    if tld.starts_with("xn--") {
        return Ok(());
    }
    // TLD should be all-alpha and at least 2 chars.
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(Error::new(ErrorKind::UnknownTld(tld.to_string()), pos));
    }
    Ok(())
}

/// PSL-based domain validation (requires `psl` feature).
#[cfg(feature = "psl")]
fn validate_psl(domain: &str, pos: usize) -> Result<(), Error> {
    use psl::Psl;

    match psl::List.suffix(domain.as_bytes()) {
        Some(suffix) if suffix.is_known() => Ok(()),
        _ => {
            let tld = domain.rsplit('.').next().unwrap_or(domain);
            Err(Error::new(ErrorKind::UnknownTld(tld.to_string()), pos))
        }
    }
}

#[cfg(not(feature = "psl"))]
fn validate_psl(domain: &str, pos: usize) -> Result<(), Error> {
    // Fallback to basic TLD check when PSL feature is disabled.
    validate_tld(domain, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_valid() {
        assert!(validate_tld("example.com", 0).is_ok());
        assert!(validate_tld("example.co.uk", 0).is_ok());
        assert!(validate_tld("example.xn--p1ai", 0).is_ok()); // .рф in punycode
    }

    #[test]
    fn tld_invalid() {
        assert!(validate_tld("example.x", 0).is_err()); // single char
        assert!(validate_tld("example.123", 0).is_err()); // numeric
    }
}
