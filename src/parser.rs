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
    /// Clean local-part with CFWS stripped (only set for obs-local-part with CFWS).
    pub local_part_clean: Option<String>,
    /// Clean domain with CFWS stripped (only set for obs-domain with CFWS).
    pub domain_clean: Option<String>,
}

impl<'a> Parsed<'a> {
    /// Effective local-part content: CFWS-stripped version if available, otherwise raw span.
    pub fn local_part_str(&self) -> &str {
        self.local_part_clean
            .as_deref()
            .unwrap_or_else(|| self.local_part.as_str(self.input))
    }

    /// Effective domain content: CFWS-stripped version if available, otherwise raw span.
    pub fn domain_str(&self) -> &str {
        self.domain_clean
            .as_deref()
            .unwrap_or_else(|| self.domain.as_str(self.input))
    }
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
    if input.is_empty() {
        return Err(Error::new(ErrorKind::Empty, 0));
    }

    // No leading/trailing trim: bare CR/LF are not strippable whitespace —
    // accepting `user@host\n` would be a header-injection hazard. Legitimate
    // leading/trailing CFWS (spaces, folding whitespace, comments) is consumed
    // by skip_cfws in Standard/Lax; a bare CR/LF is left to be rejected.
    let mut parser = Parser::new(input);
    let allow_obs = matches!(strictness, Strictness::Lax);

    // Strip leading CFWS before choosing the display-name / angle-addr path
    // (RFC 5322: a mailbox may be preceded by CFWS). Without this, a leading
    // space would divert a quoted display name to the unquoted scanner. Strict
    // (RFC 5321) forbids CFWS, so leading whitespace is left to be rejected.
    if !matches!(strictness, Strictness::Strict) {
        skip_cfws(&mut parser, 0);
    }

    // Try name-addr format: display-name? "<" addr-spec ">"
    let display_name = if allow_display_name {
        try_parse_display_name(&mut parser, allow_obs)
    } else {
        None
    };

    // `is_angle` is set only when '<' is the current character: the display-name
    // parsers stop exactly at it, and the bare case tests `peek() == '<'`. So the
    // opening bracket is always present and consumed here.
    let is_angle = display_name.is_some() || parser.peek() == Some('<');
    if is_angle {
        parser.eat('<');
    }

    // Parse addr-spec: local-part "@" domain.
    // RFC 5322 §3.2.3: local-part dot-atom permits leading [CFWS]
    // (`dot-atom = [CFWS] dot-atom-text [CFWS]`), so a comment or folding
    // whitespace before the local-part is valid. Strip it in Standard/Lax;
    // RFC 5321 Strict forbids CFWS, so a leading '(' or space is left for
    // parse_local_part to reject.
    if !matches!(strictness, Strictness::Strict) {
        skip_cfws(&mut parser, 0);
    }
    let (local_part, local_part_clean) = parse_local_part(&mut parser, strictness)?;
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
    let (domain, domain_clean) = parse_domain(&mut parser, strictness, allow_domain_literal)?;

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
        input,
        display_name,
        local_part,
        domain,
        comments: parser.comments,
        local_part_clean,
        domain_clean,
    })
}

/// Try to parse a display name before `<`. Returns None and resets position on failure.
fn try_parse_display_name(parser: &mut Parser<'_>, allow_obs: bool) -> Option<Span> {
    let save = parser.save();

    // Quoted display name: "Name" <addr>
    if parser.peek() == Some('"') {
        let start = parser.pos;
        if parse_quoted_string(parser, allow_obs).is_err() {
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
///
/// Returns `(span, clean)` where `clean` is `Some(String)` when obs-local-part
/// contained CFWS that was stripped from the semantic value.
fn parse_local_part(
    parser: &mut Parser<'_>,
    strictness: Strictness,
) -> Result<(Span, Option<String>), Error> {
    let start = parser.pos;
    let allow_obs = matches!(strictness, Strictness::Lax);

    // Reject quoted-string local parts in Strict mode (RFC 5321 envelope).
    if parser.peek() == Some('"') {
        if matches!(strictness, Strictness::Strict) {
            return Err(parser.error(ErrorKind::InvalidLocalPartChar { ch: '"' }));
        }
        if !allow_obs {
            // Standard mode: quoted-string is the entire local-part.
            parse_quoted_string(parser, false)?;
            return Ok((Span::new(start, parser.pos), None));
        }
        // Lax mode: fall through — obs-local-part allows quoted-string as first word,
        // followed by optional "." word segments.
    }

    // dot-atom (or obs-local-part if Lax). parse_dot_atom_local always consumes
    // at least one token or returns an error, so the span is never empty here.
    let clean = parse_dot_atom_local(parser, allow_obs)?;

    Ok((Span::new(start, parser.pos), clean))
}

/// Parse dot-atom for local-part: `atext+ ("." atext+)*`.
/// If `allow_obs` is true, allows CFWS between atoms (obs-local-part).
///
/// Returns `Some(clean)` when obs-mode CFWS was present and stripped,
/// `None` when the span is already clean (zero-copy path).
fn parse_dot_atom_local(parser: &mut Parser<'_>, allow_obs: bool) -> Result<Option<String>, Error> {
    if !allow_obs {
        // Standard mode: no CFWS between atoms, span is always clean.
        if !eat_atext_run(parser) {
            return Err(match parser.peek() {
                Some(ch) if ch != '@' => parser.error(ErrorKind::InvalidLocalPartChar { ch }),
                _ => parser.error(ErrorKind::EmptyLocalPart),
            });
        }
        loop {
            let save = parser.save();
            if !parser.eat('.') {
                parser.restore(save);
                break;
            }
            if !eat_atext_run(parser) {
                return Err(parser.error(ErrorKind::EmptyLocalPart));
            }
        }
        return Ok(None);
    }

    // Obs mode: parse atoms, building a clean string only when CFWS is present.
    // Zero allocation in the common no-CFWS path. When CFWS is first detected,
    // the contiguous prefix (all prior atoms+dots, no CFWS gaps) is copied
    // from the raw span, then subsequent atoms are appended incrementally.
    let mut clean: Option<String> = None;
    let outer_start = parser.pos;

    // First word: any leading CFWS was already consumed by the caller (`parse`
    // skips it before the local-part). CFWS stripping here applies only between
    // segments, so the first word starts immediately.
    if !eat_atext_run(parser) && !try_quoted_string(parser, allow_obs) {
        return Err(match parser.peek() {
            Some(ch) if ch != '@' => parser.error(ErrorKind::InvalidLocalPartChar { ch }),
            _ => parser.error(ErrorKind::EmptyLocalPart),
        });
    }

    // Subsequent ".atom" segments
    loop {
        // `last_clean_end` marks the end of contiguous clean content before
        // any CFWS in this iteration. Used as prefix boundary if CFWS is
        // detected for the first time.
        let last_clean_end = parser.pos;
        let save = parser.save();
        let comments_len = parser.comments.len();
        skip_cfws(parser, 0);
        let had_cfws_before_dot = parser.pos > last_clean_end;
        if !parser.eat('.') {
            parser.restore(save);
            parser.comments.truncate(comments_len);
            break;
        }
        if had_cfws_before_dot && clean.is_none() {
            let mut s = String::with_capacity(last_clean_end - outer_start);
            s.push_str(&parser.input[outer_start..last_clean_end]);
            clean = Some(s);
        }
        skip_cfws(parser, 0);
        // If CFWS after dot and we haven't started clean yet, seed with
        // content before the dot — the dot is appended below via push('.').
        if clean.is_none() && parser.pos > last_clean_end + 1 {
            let mut s = String::with_capacity(last_clean_end - outer_start);
            s.push_str(&parser.input[outer_start..last_clean_end]);
            clean = Some(s);
        }
        let atom_start = parser.pos;
        if !eat_atext_run(parser) && !try_quoted_string(parser, allow_obs) {
            return Err(parser.error(ErrorKind::EmptyLocalPart));
        }
        if let Some(ref mut s) = clean {
            s.push('.');
            s.push_str(&parser.input[atom_start..parser.pos]);
        }
    }

    Ok(clean)
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

/// Parse quoted-string: `"` (qtext | quoted-pair | FWS)* `"`.
///
/// With `allow_obs`, accepts obs-qtext and obs-qp (control characters) per
/// RFC 5322 §4.1 — used in Lax mode.
fn parse_quoted_string(parser: &mut Parser<'_>, allow_obs: bool) -> Result<(), Error> {
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
                    Some(ch) if is_quoted_pair_char(ch, allow_obs) => {}
                    _ => return Err(parser.error(ErrorKind::InvalidQuotedPair)),
                }
            }
            Some(ch) if is_qtext(ch, allow_obs) => {
                parser.advance();
            }
            // RFC 5322 FWS: plain WSP or CRLF + WSP (folded whitespace).
            Some(ch) if is_wsp(ch) || ch == '\r' => {
                if !try_eat_fws(parser) {
                    return Err(parser.error(ErrorKind::InvalidLocalPartChar { ch: '\r' }));
                }
            }
            None => return Err(parser.error(ErrorKind::UnterminatedQuotedString)),
            Some(ch) => {
                return Err(parser.error(ErrorKind::InvalidLocalPartChar { ch }));
            }
        }
    }
}

/// Try to parse a quoted-string without error on failure.
fn try_quoted_string(parser: &mut Parser<'_>, allow_obs: bool) -> bool {
    if parser.peek() != Some('"') {
        return false;
    }
    let save = parser.save();
    if parse_quoted_string(parser, allow_obs).is_ok() {
        true
    } else {
        parser.restore(save);
        false
    }
}

/// Parse domain: dot-atom / domain-literal / obs-domain.
///
/// Returns `(span, clean)` where `clean` is `Some(String)` when obs-domain
/// contained CFWS that was stripped from the semantic value.
fn parse_domain(
    parser: &mut Parser<'_>,
    strictness: Strictness,
    allow_domain_literal: bool,
) -> Result<(Span, Option<String>), Error> {
    let start = parser.pos;

    // Domain literal: [...]
    if parser.peek() == Some('[') {
        if !allow_domain_literal {
            return Err(parser.error(ErrorKind::InvalidDomainChar { ch: '[' }));
        }
        parse_domain_literal(parser)?;
        return Ok((Span::new(start, parser.pos), None));
    }

    // dot-atom domain. parse_dot_atom_domain parses at least one label or
    // returns an error, so the span is never empty here.
    let allow_obs = matches!(strictness, Strictness::Lax);
    let clean = parse_dot_atom_domain(parser, allow_obs)?;

    Ok((Span::new(start, parser.pos), clean))
}

/// Parse dot-atom for domain: `label ("." label)*` where label avoids leading/trailing hyphen.
///
/// Returns `Some(clean)` when obs-mode CFWS was present and stripped,
/// `None` when the span is already clean (zero-copy path).
fn parse_dot_atom_domain(
    parser: &mut Parser<'_>,
    allow_obs: bool,
) -> Result<Option<String>, Error> {
    if !allow_obs {
        // Standard mode: no CFWS between labels, span is always clean.
        parse_domain_label(parser)?;
        loop {
            let save = parser.save();
            if !parser.eat('.') {
                parser.restore(save);
                break;
            }
            parse_domain_label(parser)?;
        }
        return Ok(None);
    }

    // Obs mode: parse labels, building a clean string only when CFWS is present.
    // Zero allocation in the common no-CFWS path. Same incremental strategy
    // as parse_dot_atom_local — see that function for detailed comments.
    let mut clean: Option<String> = None;
    let outer_start = parser.pos;

    parse_domain_label(parser)?;

    loop {
        let last_clean_end = parser.pos;
        let save = parser.save();
        let comments_len = parser.comments.len();
        skip_cfws(parser, 0);
        let had_cfws_before_dot = parser.pos > last_clean_end;
        if !parser.eat('.') {
            parser.restore(save);
            parser.comments.truncate(comments_len);
            break;
        }
        if had_cfws_before_dot && clean.is_none() {
            let mut s = String::with_capacity(last_clean_end - outer_start);
            s.push_str(&parser.input[outer_start..last_clean_end]);
            clean = Some(s);
        }
        skip_cfws(parser, 0);
        if clean.is_none() && parser.pos > last_clean_end + 1 {
            let mut s = String::with_capacity(last_clean_end - outer_start);
            s.push_str(&parser.input[outer_start..last_clean_end]);
            clean = Some(s);
        }
        let label_start = parser.pos;
        parse_domain_label(parser)?;
        if let Some(ref mut s) = clean {
            s.push('.');
            s.push_str(&parser.input[label_start..parser.pos]);
        }
    }

    Ok(clean)
}

/// Parse a single domain label: starts and ends with alnum, may contain hyphens.
fn parse_domain_label(parser: &mut Parser<'_>) -> Result<(), Error> {
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

    Ok(())
}

/// Parse domain literal: `[` ... `]`, accepting only valid RFC 5321 §4.1.3
/// address literals — an IPv4 dotted-quad or an `IPv6:`-tagged IPv6 address.
///
/// General RFC 5322 domain literals (arbitrary `dtext`, e.g.
/// `[RFC-5322-domain-literal]`) and malformed IP literals (`[255.255.255]`,
/// `[IPv6:1::2:]`) are syntactically consumed but rejected with
/// [`ErrorKind::InvalidAddressLiteral`]: a non-IP literal is not a usable mail
/// destination. This matches the isEmail conformance baseline, which classifies
/// such tokens as RFC 5322-only (not valid RFC 5321 addresses).
fn parse_domain_literal(parser: &mut Parser<'_>) -> Result<(), Error> {
    let open = parser.pos;
    if !parser.eat('[') {
        return Err(parser.error(ErrorKind::UnterminatedDomainLiteral));
    }
    let content_start = parser.pos;
    loop {
        match parser.peek() {
            Some(']') => {
                let content = &parser.input[content_start..parser.pos];
                parser.advance(); // consume ']'
                if is_address_literal(content) {
                    return Ok(());
                }
                return Err(Error::new(ErrorKind::InvalidAddressLiteral, open));
            }
            // A backslash escapes the next char (obs-dtext); consume both so an
            // escaped ']' does not close the literal early. The resulting
            // content fails IP validation above, so the literal is rejected.
            Some('\\') => {
                parser.advance();
                if parser.advance().is_none() {
                    return Err(parser.error(ErrorKind::UnterminatedDomainLiteral));
                }
            }
            None => return Err(parser.error(ErrorKind::UnterminatedDomainLiteral)),
            Some(_) => {
                parser.advance();
            }
        }
    }
}

/// Returns true if the domain-literal content (the text between `[` and `]`)
/// is a valid IPv4 address literal or an `IPv6:`-tagged IPv6 address literal
/// (RFC 5321 §4.1.3). Uses `core::net` parsers (no-std friendly).
fn is_address_literal(content: &str) -> bool {
    use core::net::{Ipv4Addr, Ipv6Addr};
    // The "IPv6:" tag is an ABNF string literal, hence case-insensitive
    // (RFC 5234 §2.3): `[ipv6:::1]` and `[IPV6:...]` are equally valid.
    if content
        .get(..5)
        .is_some_and(|tag| tag.eq_ignore_ascii_case("IPv6:"))
    {
        return content[5..].parse::<Ipv6Addr>().is_ok();
    }
    content.parse::<Ipv4Addr>().is_ok()
}

/// Try to consume one FWS token: either plain WSP, or CRLF followed by at least one WSP.
/// Returns true if any whitespace was consumed.
fn try_eat_fws(parser: &mut Parser<'_>) -> bool {
    match parser.peek() {
        Some(ch) if is_wsp(ch) => {
            parser.advance();
            // Consume any additional WSP
            while let Some(ch) = parser.peek() {
                if is_wsp(ch) {
                    parser.advance();
                } else {
                    break;
                }
            }
            true
        }
        Some('\r') => {
            let pos = parser.pos;
            let bytes = parser.input.as_bytes();
            if pos + 2 < bytes.len()
                && bytes[pos] == b'\r'
                && bytes[pos + 1] == b'\n'
                && (bytes[pos + 2] == b' ' || bytes[pos + 2] == b'\t')
            {
                parser.advance(); // '\r'
                parser.advance(); // '\n'
                while let Some(ch) = parser.peek() {
                    if is_wsp(ch) {
                        parser.advance();
                    } else {
                        break;
                    }
                }
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Skip CFWS (comments and folding whitespace). `depth` seeds the comment
/// nesting counter; recursion is bounded by [`parse_comment`].
fn skip_cfws(parser: &mut Parser<'_>, depth: usize) {
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
                        parser.advance(); // '\n', then consume following WSP
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
                    // Intentionally swallowing comment parse errors here.
                    // skip_cfws is called in contexts where '(' may not start a comment
                    // (e.g., trailing garbage after addr-spec). Propagating the error
                    // would mask the real issue. Instead, restore position and let the
                    // caller produce a context-appropriate error (Unexpected, MissingAtSign, etc.).
                    parser.pos = comment_start;
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
            // A comment is free-form CFWS: a backslash escapes any following
            // character (including obs-qp control chars). Only a trailing
            // backslash at end-of-input is an error.
            Some('\\') => {
                parser.advance();
                if parser.advance().is_none() {
                    return Err(parser.error(ErrorKind::UnterminatedComment));
                }
            }
            Some(ch) if is_ctext(ch) || is_wsp(ch) => {
                parser.advance();
            }
            // Inside a comment, CR/LF is only valid as folding whitespace
            // (CRLF + WSP). A bare CR or LF is invalid (e.g. `(\r)`).
            Some('\r') | Some('\n') => {
                if !try_eat_fws(parser) {
                    return Err(parser.error(ErrorKind::UnterminatedComment));
                }
            }
            None => return Err(parser.error(ErrorKind::UnterminatedComment)),
            Some(_) => {
                parser.advance(); // be lenient in comments (obs-ctext controls)
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

/// qtext (RFC 5322 §3.2.4): printable ASCII except `"` and `\`, plus UTF-8
/// non-ASCII. With `allow_obs`, also accepts obs-qtext (obs-NO-WS-CTL controls).
fn is_qtext(ch: char, allow_obs: bool) -> bool {
    if ch == '"' || ch == '\\' {
        return false;
    }
    is_printable_ascii(ch) || is_utf8_non_ascii(ch) || (allow_obs && is_obs_no_ws_ctl(ch))
}

/// ctext: printable ASCII except `(`, `)`, `\`, plus UTF-8 non-ASCII.
fn is_ctext(ch: char) -> bool {
    ch != '(' && ch != ')' && ch != '\\' && (is_printable_ascii(ch) || is_utf8_non_ascii(ch))
}

/// Characters valid in a quoted-pair after `\` (RFC 5322 §3.2.1: `quoted-pair =
/// "\" (VCHAR / WSP)`). Non-ASCII is intentionally excluded — RFC 6531 allows
/// UTF-8 directly in qtext, so escaping it is invalid. With `allow_obs`, also
/// accepts obs-qp: NUL, CR, LF, and obs-NO-WS-CTL controls.
fn is_quoted_pair_char(ch: char, allow_obs: bool) -> bool {
    if is_printable_ascii(ch) || is_wsp(ch) {
        return true;
    }
    allow_obs && (matches!(ch, '\0' | '\n' | '\r') || is_obs_no_ws_ctl(ch))
}

/// obs-NO-WS-CTL (RFC 5322 §4.1): control chars usable in obsolete qtext and
/// quoted-pairs — %d1-8, %d11, %d12, %d14-31, %d127 (excludes NUL, TAB, LF, CR).
fn is_obs_no_ws_ctl(ch: char) -> bool {
    matches!(ch as u32, 0x01..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f)
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
mod tests;
