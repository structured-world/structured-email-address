//! Hand-rolled RFC 5321/5322/6531 email address parser.
//!
//! Grammar reference: RFC 5322 §3.4.1 (addr-spec), §3.2.3 (atom, dot-atom),
//! §3.2.4 (quoted-string), §3.2.2 (FWS, CFWS), §4.4 (obs-local-part, obs-domain),
//! RFC 6531 §3.3 (UTF8-non-ascii in atext/qtext/dtext).
//!
//! This parser produces zero-copy byte-offset spans into the input string.

use crate::config::Strictness;
use crate::error::{Error, ErrorKind};

/// Maximum nesting depth for comments and obs-domain recursion.
const MAX_RECURSION_DEPTH: usize = 128;

/// Raw parse result with byte-offset spans into the input.
#[derive(Debug, Clone)]
pub(crate) struct Parsed<'a> {
    /// The original input.
    pub input: &'a str,
    /// Display name (from `name-addr` syntax), if present.
    pub display_name: Option<Span>,
    /// Full local-part span (may include quotes for quoted-string).
    pub local_part: Span,
    /// Domain span.
    pub domain: Span,
    /// Comments found during parsing.
    #[allow(dead_code)]
    pub comments: Vec<Span>,
}

/// A byte-offset range into the input string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn as_str<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}

/// Parser state: tracks current position in the input.
struct Parser<'a> {
    input: &'a str,
    pos: usize,
    comments: Vec<Span>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            comments: Vec::new(),
        }
    }

    /// Remaining unparsed input.
    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    /// Peek at the next character without consuming.
    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    /// Consume and return the next character.
    fn advance(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    /// Consume the next character if it matches.
    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    /// Check if we've consumed all input.
    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Create an error at the current position.
    fn error(&self, kind: ErrorKind) -> Error {
        Error::new(kind, self.pos)
    }

    /// Save current position for backtracking.
    fn save(&self) -> usize {
        self.pos
    }

    /// Restore position for backtracking.
    fn restore(&mut self, pos: usize) {
        self.pos = pos;
    }
}

/// Parse an email address string according to the given strictness level.
///
/// If `allow_display_name` is true, accepts `name-addr` format: `"Name" <addr>` or `Name <addr>`.
pub(crate) fn parse(
    input: &str,
    strictness: Strictness,
    allow_display_name: bool,
    allow_domain_literal: bool,
) -> Result<Parsed<'_>, Error> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::new(ErrorKind::Empty, 0));
    }

    let mut parser = Parser::new(trimmed);

    // Try name-addr format: display-name? "<" addr-spec ">"
    let display_name = if allow_display_name {
        try_parse_display_name(&mut parser)
    } else {
        None
    };

    let is_angle = display_name.is_some() || parser.peek() == Some('<');
    if is_angle {
        // Skip optional CFWS before <
        skip_cfws(&mut parser, 0);
        if !parser.eat('<') {
            return Err(parser.error(ErrorKind::Unexpected {
                ch: parser.peek().unwrap_or('\0'),
            }));
        }
    }

    // Parse addr-spec: local-part "@" domain
    let local_part = parse_local_part(&mut parser, strictness)?;
    // RFC 5322 allows CFWS around "@" in Standard/Lax modes.
    if !matches!(strictness, Strictness::Strict) {
        skip_cfws(&mut parser, 0);
    }
    if !parser.eat('@') {
        return Err(parser.error(ErrorKind::MissingAtSign));
    }
    if !matches!(strictness, Strictness::Strict) {
        skip_cfws(&mut parser, 0);
    }
    let domain = parse_domain(&mut parser, strictness, allow_domain_literal)?;

    if is_angle {
        if !matches!(strictness, Strictness::Strict) {
            skip_cfws(&mut parser, 0);
        }
        if !parser.eat('>') {
            return Err(parser.error(ErrorKind::Unexpected {
                ch: parser.peek().unwrap_or('\0'),
            }));
        }
    }

    // Skip trailing CFWS (not in Strict mode — RFC 5321 forbids comments/CFWS).
    if !matches!(strictness, Strictness::Strict) {
        skip_cfws(&mut parser, 0);
    }

    if !parser.at_end() {
        let ch = parser.peek().unwrap_or('\0');
        return Err(parser.error(ErrorKind::Unexpected { ch }));
    }

    Ok(Parsed {
        input: trimmed,
        display_name,
        local_part,
        domain,
        comments: parser.comments,
    })
}

/// Try to parse a display name before `<`. Returns None and resets position on failure.
fn try_parse_display_name(parser: &mut Parser<'_>) -> Option<Span> {
    let save = parser.save();

    // Quoted display name: "Name" <addr>
    if parser.peek() == Some('"') {
        let start = parser.pos;
        if parse_quoted_string(parser).is_err() {
            parser.restore(save);
            return None;
        }
        let end = parser.pos;
        skip_cfws(parser, 0);
        if parser.peek() == Some('<') {
            // Span excludes quotes
            return Some(Span::new(start + 1, end - 1));
        }
        parser.restore(save);
        return None;
    }

    // Unquoted display name: word+ before <
    let start = parser.pos;
    let mut found_content = false;
    loop {
        match parser.peek() {
            Some('<') if found_content => {
                // Trim trailing whitespace from display name
                let name = &parser.input[start..parser.pos];
                let trimmed_end = start + name.trim_end().len();
                return Some(Span::new(start, trimmed_end));
            }
            Some(ch) if ch == '@' || ch == '>' => {
                // Not a display name — probably bare addr-spec
                parser.restore(save);
                return None;
            }
            Some(ch) if ch < '\u{20}' && ch != '\t' => {
                // Control characters are not valid in display names.
                parser.restore(save);
                return None;
            }
            Some(_) => {
                found_content = true;
                parser.advance();
            }
            None => {
                parser.restore(save);
                return None;
            }
        }
    }
}

/// Parse local-part: dot-atom / quoted-string / obs-local-part.
fn parse_local_part(parser: &mut Parser<'_>, strictness: Strictness) -> Result<Span, Error> {
    let start = parser.pos;
    let allow_obs = matches!(strictness, Strictness::Lax);

    // Reject quoted-string local parts in Strict mode (RFC 5321 envelope).
    if parser.peek() == Some('"') {
        if matches!(strictness, Strictness::Strict) {
            return Err(parser.error(ErrorKind::InvalidLocalPartChar { ch: '"' }));
        }
        if !allow_obs {
            // Standard mode: quoted-string is the entire local-part.
            parse_quoted_string(parser)?;
            return Ok(Span::new(start, parser.pos));
        }
        // Lax mode: fall through — obs-local-part allows quoted-string as first word,
        // followed by optional "." word segments.
    }

    // dot-atom (or obs-local-part if Lax)
    parse_dot_atom_local(parser, allow_obs)?;

    let end = parser.pos;
    if end == start {
        return Err(parser.error(ErrorKind::EmptyLocalPart));
    }

    Ok(Span::new(start, end))
}

/// Parse dot-atom for local-part: `atext+ ("." atext+)*`.
/// If `allow_obs` is true, allows CFWS between atoms (obs-local-part).
// TODO: CFWS between atoms is included in the Span — strip it for clean semantics (#13)
fn parse_dot_atom_local(parser: &mut Parser<'_>, allow_obs: bool) -> Result<(), Error> {
    // First word: atext-run, or (in obs mode) optional CFWS + atext-run or quoted-string.
    if allow_obs {
        skip_cfws(parser, 0);
        if !eat_atext_run(parser) && !try_quoted_string(parser) {
            return Err(parser.error(ErrorKind::EmptyLocalPart));
        }
    } else if !eat_atext_run(parser) {
        return Err(parser.error(ErrorKind::EmptyLocalPart));
    }

    // Subsequent ".atom" segments
    loop {
        let save = parser.save();
        if allow_obs {
            skip_cfws(parser, 0);
        }
        if !parser.eat('.') {
            parser.restore(save);
            break;
        }
        if allow_obs {
            skip_cfws(parser, 0);
        }
        if allow_obs {
            // In obs mode, allow either another atext run or a quoted-string segment.
            if !eat_atext_run(parser) && !try_quoted_string(parser) {
                // Trailing dot or invalid local-part after consuming '.' — report an error
                // instead of backtracking and truncating the local-part.
                return Err(parser.error(ErrorKind::EmptyLocalPart));
            }
        } else {
            // In standard mode, quoted-string after '.' is not allowed (no obs-local-part).
            if !eat_atext_run(parser) {
                // Trailing dot: "." must be followed by another atom/quoted-string.
                // Report an explicit local-part error instead of backtracking and truncating.
                return Err(parser.error(ErrorKind::EmptyLocalPart));
            }
        }
    }

    Ok(())
}

/// Consume one or more atext characters. Returns true if any consumed.
fn eat_atext_run(parser: &mut Parser<'_>) -> bool {
    let start = parser.pos;
    while let Some(ch) = parser.peek() {
        if is_atext(ch) {
            parser.advance();
        } else {
            break;
        }
    }
    parser.pos > start
}

/// Parse quoted-string: `"` (qtext | quoted-pair)* `"`.
fn parse_quoted_string(parser: &mut Parser<'_>) -> Result<(), Error> {
    if !parser.eat('"') {
        return Err(parser.error(ErrorKind::UnterminatedQuotedString));
    }

    loop {
        match parser.peek() {
            Some('"') => {
                parser.advance();
                return Ok(());
            }
            Some('\\') => {
                parser.advance();
                match parser.advance() {
                    Some(ch) if is_quoted_pair_char(ch) => {}
                    _ => return Err(parser.error(ErrorKind::InvalidQuotedPair)),
                }
            }
            Some(ch) if is_qtext(ch) => {
                parser.advance();
            }
            Some(ch) if is_wsp(ch) => {
                parser.advance(); // FWS within quoted string
            }
            None => return Err(parser.error(ErrorKind::UnterminatedQuotedString)),
            Some(ch) => {
                return Err(parser.error(ErrorKind::InvalidLocalPartChar { ch }));
            }
        }
    }
}

/// Try to parse a quoted-string without error on failure.
fn try_quoted_string(parser: &mut Parser<'_>) -> bool {
    if parser.peek() != Some('"') {
        return false;
    }
    let save = parser.save();
    if parse_quoted_string(parser).is_ok() {
        true
    } else {
        parser.restore(save);
        false
    }
}

/// Parse domain: dot-atom / domain-literal / obs-domain.
fn parse_domain(
    parser: &mut Parser<'_>,
    strictness: Strictness,
    allow_domain_literal: bool,
) -> Result<Span, Error> {
    let start = parser.pos;

    // Domain literal: [...]
    if parser.peek() == Some('[') {
        if !allow_domain_literal {
            return Err(parser.error(ErrorKind::InvalidDomainChar { ch: '[' }));
        }
        parse_domain_literal(parser, strictness)?;
        return Ok(Span::new(start, parser.pos));
    }

    // dot-atom domain
    let allow_obs = matches!(strictness, Strictness::Lax);
    parse_dot_atom_domain(parser, allow_obs)?;

    let end = parser.pos;
    if end == start {
        return Err(parser.error(ErrorKind::EmptyDomain));
    }

    Ok(Span::new(start, end))
}

/// Parse dot-atom for domain: `label ("." label)*` where label avoids leading/trailing hyphen.
// TODO: CFWS between labels is included in the Span — strip it for clean semantics (#13)
fn parse_dot_atom_domain(parser: &mut Parser<'_>, allow_obs: bool) -> Result<(), Error> {
    parse_domain_label(parser)?;

    loop {
        let save = parser.save();
        if allow_obs {
            skip_cfws(parser, 0);
        }
        if !parser.eat('.') {
            parser.restore(save);
            break;
        }
        if allow_obs {
            skip_cfws(parser, 0);
        }
        if parse_domain_label(parser).is_err() {
            parser.restore(save);
            break;
        }
    }

    Ok(())
}

/// Parse a single domain label: starts and ends with alnum, may contain hyphens.
fn parse_domain_label(parser: &mut Parser<'_>) -> Result<(), Error> {
    let start = parser.pos;

    // First char must be alnum (or UTF-8 non-ASCII for IDN)
    match parser.peek() {
        Some(ch) if ch.is_ascii_alphanumeric() || is_utf8_non_ascii(ch) => {
            parser.advance();
        }
        Some('-') => return Err(parser.error(ErrorKind::DomainLabelHyphen)),
        _ => return Err(parser.error(ErrorKind::EmptyDomain)),
    }

    // Continue with alnum and hyphens
    let mut last_was_hyphen = false;
    while let Some(ch) = parser.peek() {
        if ch.is_ascii_alphanumeric() || is_utf8_non_ascii(ch) {
            last_was_hyphen = false;
            parser.advance();
        } else if ch == '-' {
            last_was_hyphen = true;
            parser.advance();
        } else {
            break;
        }
    }

    if last_was_hyphen {
        return Err(parser.error(ErrorKind::DomainLabelHyphen));
    }

    if parser.pos == start {
        return Err(parser.error(ErrorKind::EmptyDomain));
    }

    Ok(())
}

/// Parse domain literal: `[` dtext* `]`.
fn parse_domain_literal(parser: &mut Parser<'_>, strictness: Strictness) -> Result<(), Error> {
    if !parser.eat('[') {
        return Err(parser.error(ErrorKind::UnterminatedDomainLiteral));
    }

    loop {
        match parser.peek() {
            Some(']') => {
                parser.advance();
                return Ok(());
            }
            // obs-dtext allows quoted-pair in Lax mode.
            Some('\\') if matches!(strictness, Strictness::Lax) => {
                parser.advance();
                match parser.advance() {
                    Some(ch) if is_quoted_pair_char(ch) => {}
                    _ => return Err(parser.error(ErrorKind::InvalidQuotedPair)),
                }
            }
            Some(ch) if is_dtext(ch) || is_wsp(ch) => {
                parser.advance();
            }
            None => return Err(parser.error(ErrorKind::UnterminatedDomainLiteral)),
            Some(ch) => {
                return Err(parser.error(ErrorKind::InvalidDomainChar { ch }));
            }
        }
    }
}

/// Skip CFWS (comments and folding whitespace).
fn skip_cfws(parser: &mut Parser<'_>, depth: usize) {
    if depth >= MAX_RECURSION_DEPTH {
        return;
    }
    loop {
        // Skip whitespace and RFC 5322 Folding White Space (CRLF + WSP).
        loop {
            match parser.peek() {
                // Regular WSP (space / tab)
                Some(ch) if is_wsp(ch) => {
                    parser.advance();
                }
                // Potential FWS: CRLF followed by WSP
                Some('\r') => {
                    let pos = parser.pos;
                    let bytes = parser.input.as_bytes();
                    // Check for CRLF + WSP as per RFC 5322 FWS
                    if pos + 2 < bytes.len()
                        && bytes[pos] == b'\r'
                        && bytes[pos + 1] == b'\n'
                        && (bytes[pos + 2] == b' ' || bytes[pos + 2] == b'\t')
                    {
                        // Consume CRLF
                        parser.advance(); // '\r'
                        parser.advance(); // '\n'
                        // Consume at least one following WSP, and any additional WSP
                        while let Some(wch) = parser.peek() {
                            if is_wsp(wch) {
                                parser.advance();
                            } else {
                                break;
                            }
                        }
                    } else {
                        // Bare CR is not valid FWS; stop treating as CFWS here.
                        break;
                    }
                }
                // Bare LF is not valid FWS; stop here.
                Some('\n') => {
                    break;
                }
                _ => break,
            }
        }
        // Try comment
        if parser.peek() == Some('(') {
            let comment_start = parser.pos;
            match parse_comment(parser, depth) {
                Ok(()) => {
                    parser.comments.push(Span::new(comment_start, parser.pos));
                    continue;
                }
                Err(_) => {
                    // Restore parser position so the caller can handle the '(' and
                    // any following characters as part of normal parsing.
                    parser.pos = comment_start;
                    // Do not attempt to parse this as CFWS again.
                    break;
                }
            }
        }
        break;
    }
}

/// Parse a comment: `(` ccontent* `)`.
fn parse_comment(parser: &mut Parser<'_>, depth: usize) -> Result<(), Error> {
    if depth >= MAX_RECURSION_DEPTH || !parser.eat('(') {
        return Err(parser.error(ErrorKind::UnterminatedComment));
    }

    loop {
        match parser.peek() {
            Some(')') => {
                parser.advance();
                return Ok(());
            }
            Some('(') => {
                // Nested comment
                parse_comment(parser, depth + 1)?;
            }
            Some('\\') => {
                parser.advance();
                match parser.advance() {
                    Some(ch) if is_quoted_pair_char(ch) => {}
                    _ => return Err(parser.error(ErrorKind::InvalidQuotedPair)),
                }
            }
            Some(ch) if is_ctext(ch) || is_wsp(ch) => {
                parser.advance();
            }
            None => return Err(parser.error(ErrorKind::UnterminatedComment)),
            Some(_) => {
                parser.advance(); // be lenient in comments
            }
        }
    }
}

// ── Character class predicates (RFC 5322 §3.2.3 + RFC 6531) ──

/// atext: ALPHA / DIGIT / special chars / UTF-8 non-ASCII.
fn is_atext(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || is_utf8_non_ascii(ch)
        || matches!(
            ch,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
        )
}

/// qtext: printable ASCII except `"` and `\`, plus UTF-8 non-ASCII.
fn is_qtext(ch: char) -> bool {
    ch != '"' && ch != '\\' && (is_printable_ascii(ch) || is_utf8_non_ascii(ch))
}

/// ctext: printable ASCII except `(`, `)`, `\`, plus UTF-8 non-ASCII.
fn is_ctext(ch: char) -> bool {
    ch != '(' && ch != ')' && ch != '\\' && (is_printable_ascii(ch) || is_utf8_non_ascii(ch))
}

/// dtext: printable ASCII except `[`, `]`, `\`, plus UTF-8 non-ASCII.
fn is_dtext(ch: char) -> bool {
    ch != '[' && ch != ']' && ch != '\\' && (is_printable_ascii(ch) || is_utf8_non_ascii(ch))
}

/// Characters valid in a quoted-pair after `\`.
fn is_quoted_pair_char(ch: char) -> bool {
    is_printable_ascii(ch) || is_wsp(ch) || is_utf8_non_ascii(ch)
}

fn is_printable_ascii(ch: char) -> bool {
    matches!(ch as u32, 0x21..=0x7e)
}

fn is_utf8_non_ascii(ch: char) -> bool {
    (ch as u32) >= 0x80
}

fn is_wsp(ch: char) -> bool {
    ch == ' ' || ch == '\t'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(input: &str) -> Parsed<'_> {
        parse(input, Strictness::Standard, false, false)
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"))
    }

    #[allow(dead_code)]
    fn parse_ok_lax(input: &str) -> Parsed<'_> {
        parse(input, Strictness::Lax, false, false)
            .unwrap_or_else(|e| panic!("failed to parse '{input}': {e}"))
    }

    fn parse_err(input: &str) -> Error {
        parse(input, Strictness::Standard, false, false)
            .expect_err(&format!("expected error for '{input}'"))
    }

    // ── Basic valid addresses ──

    #[test]
    fn simple_address() {
        let p = parse_ok("user@example.com");
        assert_eq!(p.local_part.as_str(p.input), "user");
        assert_eq!(p.domain.as_str(p.input), "example.com");
    }

    #[test]
    fn subaddress_preserved() {
        let p = parse_ok("user+tag@example.com");
        assert_eq!(p.local_part.as_str(p.input), "user+tag");
    }

    #[test]
    fn dotted_local() {
        let p = parse_ok("first.last@example.com");
        assert_eq!(p.local_part.as_str(p.input), "first.last");
    }

    #[test]
    fn utf8_local() {
        let p = parse_ok("дмитрий@example.com");
        assert_eq!(p.local_part.as_str(p.input), "дмитрий");
    }

    #[test]
    fn utf8_domain() {
        let p = parse_ok("user@münchen.de");
        assert_eq!(p.domain.as_str(p.input), "münchen.de");
    }

    #[test]
    fn quoted_local_part() {
        let p = parse_ok("\"user@name\"@example.com");
        assert_eq!(p.local_part.as_str(p.input), "\"user@name\"");
    }

    #[test]
    fn quoted_local_with_spaces() {
        let p = parse_ok("\"user name\"@example.com");
        assert_eq!(p.local_part.as_str(p.input), "\"user name\"");
    }

    // ── Invalid addresses ──

    #[test]
    fn empty_input() {
        let e = parse_err("");
        assert_eq!(e.kind(), &ErrorKind::Empty);
    }

    #[test]
    fn no_at_sign() {
        let e = parse_err("userexample.com");
        assert_eq!(e.kind(), &ErrorKind::MissingAtSign);
    }

    #[test]
    fn empty_local() {
        let e = parse_err("@example.com");
        assert_eq!(e.kind(), &ErrorKind::EmptyLocalPart);
    }

    #[test]
    fn empty_domain() {
        let e = parse_err("user@");
        assert_eq!(e.kind(), &ErrorKind::EmptyDomain);
    }

    // ── Dot-atom edge cases ──

    #[test]
    fn trailing_dot_in_local_part_is_not_missing_at_sign() {
        let e = parse_err("user.@example.com");
        // Ensure this is treated as a local-part syntax error, not as a missing '@'.
        assert_ne!(e.kind(), &ErrorKind::MissingAtSign);
    }

    #[test]
    fn obs_local_part_quoted_first_word() {
        // obs-local-part: word *("." word), where word can be quoted-string.
        // "a".b@example.com must parse in Lax mode.
        let p = parse("\"a\".b@example.com", Strictness::Lax, false, false).unwrap_or_else(|e| {
            panic!("Lax must accept obs-local-part starting with quoted word: {e}")
        });
        assert_eq!(p.local_part.as_str(p.input), "\"a\".b");
        assert_eq!(p.domain.as_str(p.input), "example.com");
    }

    #[test]
    fn obs_local_part_rejected_in_standard() {
        let e = parse("a.\"b\"@example.com", Strictness::Standard, false, false)
            .expect_err("expected obs-local-part to be rejected in Standard strictness");
        // Should fail due to local-part syntax, not due to a missing '@'.
        assert_ne!(e.kind(), &ErrorKind::MissingAtSign);
    }

    #[test]
    fn obs_local_part_accepted_in_lax() {
        let p = parse("a.\"b\"@example.com", Strictness::Lax, false, false)
            .unwrap_or_else(|e| panic!("parse failed in Lax strictness: {e}"));
        assert_eq!(p.local_part.as_str(p.input), "a.\"b\"");
        assert_eq!(p.domain.as_str(p.input), "example.com");
    }

    // ── Display name ──

    #[test]
    fn display_name_angle() {
        let p = parse(
            "John Doe <user@example.com>",
            Strictness::Standard,
            true,
            false,
        )
        .unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(p.display_name.map(|s| s.as_str(p.input)), Some("John Doe"));
        assert_eq!(p.local_part.as_str(p.input), "user");
        assert_eq!(p.domain.as_str(p.input), "example.com");
    }

    #[test]
    fn quoted_display_name() {
        let p = parse(
            "\"John Doe\" <user@example.com>",
            Strictness::Standard,
            true,
            false,
        )
        .unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(p.display_name.map(|s| s.as_str(p.input)), Some("John Doe"));
    }

    // ── Domain literal ──

    #[test]
    fn domain_literal_allowed() {
        let p = parse("user@[192.168.1.1]", Strictness::Standard, false, true)
            .unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(p.domain.as_str(p.input), "[192.168.1.1]");
    }

    #[test]
    fn strict_rejects_trailing_comment() {
        // RFC 5321 Strict mode must not accept trailing comments/CFWS.
        let e = parse(
            "user@example.com (comment)",
            Strictness::Strict,
            false,
            false,
        )
        .expect_err("Strict mode must reject trailing comment");
        assert!(matches!(e.kind(), ErrorKind::Unexpected { .. }));
    }

    #[test]
    fn strict_rejects_trailing_cfws_in_angle() {
        // Trailing CFWS between domain and '>' in Strict mode.
        let e = parse(
            "<user@example.com (comment)>",
            Strictness::Strict,
            false,
            false,
        )
        .expect_err("Strict mode must reject CFWS before closing angle bracket");
        assert!(matches!(e.kind(), ErrorKind::Unexpected { .. }));
    }

    #[test]
    fn domain_literal_rejected_by_default() {
        let e = parse("user@[192.168.1.1]", Strictness::Standard, false, false)
            .expect_err("expected error");
        assert_eq!(e.kind(), &ErrorKind::InvalidDomainChar { ch: '[' });
    }
}
