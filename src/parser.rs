//! Hand-rolled RFC 5321/5322/6531 email address parser.
//!
//! Grammar reference: RFC 5322 §3.4.1 (addr-spec), §3.2.3 (atom, dot-atom),
//! §3.2.4 (quoted-string), §3.2.2 (FWS, CFWS), §4.4 (obs-local-part, obs-domain),
//! RFC 5321 §4.1.2 (Mailbox, Quoted-string), RFC 6531 §3.3 (UTF8-non-ascii in
//! atext/qtext/dtext).
//!
//! This parser produces zero-copy byte-offset spans into the input string.

use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{AddressLiteral, Config, Strictness};
use crate::error::{Error, ErrorKind};

/// Maximum nesting depth for comments and obs-domain recursion.
const MAX_RECURSION_DEPTH: usize = 128;

/// Which quoted-string grammar a `"..."` run is read against.
///
/// The two mail specifications spell the same construct differently, and the
/// difference is not decorative: the envelope alphabet is the narrower of the
/// two, so a local part that only the header grammar admits cannot enter
/// through the envelope one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quoted {
    /// `qtextSMTP` / `quoted-pairSMTP` (RFC 5321 §4.1.2), extended with
    /// `UTF8-non-ascii` (RFC 6531 §3.3).
    ///
    /// ```text
    /// qtextSMTP       = %d32-33 / %d35-91 / %d93-126
    /// quoted-pairSMTP = %d92 %d32-126
    /// ```
    ///
    /// Space is content rather than folding whitespace, and nothing else that
    /// is not a printable ASCII character is reachable: no tab, no CRLF
    /// folding, no control character behind a backslash.
    Smtp,
    /// `qtext` / `quoted-pair` (RFC 5322 §3.2.4, §3.2.1), with FWS.
    Header,
    /// [`Header`](Self::Header) plus `obs-qtext` and `obs-qp` (RFC 5322 §4.1).
    Obsolete,
}

impl Quoted {
    /// The header alphabet, in its obsolete reading when Lax mode asked for one.
    fn header(allow_obs: bool) -> Self {
        if allow_obs {
            Self::Obsolete
        } else {
            Self::Header
        }
    }
}

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

/// Parse an email address string against the grammar the config selects.
///
/// Takes the whole [`Config`], as the other two stages of the pipeline do,
/// rather than a widening list of grammar knobs: four of them are already
/// enough for a call site to pass one flag where it meant the other.
pub(crate) fn parse<'a>(input: &'a str, config: &Config) -> Result<Parsed<'a>, Error> {
    let strictness = config.strictness;
    let address_literal = config.address_literal;

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
    let display_name = if config.allow_display_name {
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
    let (local_part, local_part_clean) =
        parse_local_part(&mut parser, strictness, config.quoted_local_part)?;
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
    let (domain, domain_clean) = parse_domain(&mut parser, strictness, address_literal)?;

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
        if parse_quoted_string(parser, Quoted::header(allow_obs)).is_err() {
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
    quoted_local_part: bool,
) -> Result<(Span, Option<String>), Error> {
    let start = parser.pos;
    let allow_obs = matches!(strictness, Strictness::Lax);

    if parser.peek() == Some('"') {
        if matches!(strictness, Strictness::Strict) {
            // `Local-part = Dot-string / Quoted-string` (RFC 5321 §4.1.2). The
            // second alternative is off by default because Strict exists to
            // refuse addresses that are valid but unroutable in practice; a
            // caller reading an identity rather than routing to it asks for it
            // back. It is then the whole local part — the envelope grammar has
            // no obs-local-part to continue it with — and it is read against
            // the envelope alphabet, narrower than the header one, so it cannot
            // become a way in for a spelling only RFC 5322 admits.
            if !quoted_local_part {
                return Err(parser.error(ErrorKind::InvalidLocalPartChar { ch: '"' }));
            }
            parse_quoted_string(parser, Quoted::Smtp)?;
            return Ok((Span::new(start, parser.pos), None));
        }
        if !allow_obs {
            // Standard mode: quoted-string is the entire local-part.
            parse_quoted_string(parser, Quoted::Header)?;
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
    if !eat_atext_run(parser) && !try_quoted_string(parser, Quoted::header(allow_obs)) {
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
        if !eat_atext_run(parser) && !try_quoted_string(parser, Quoted::header(allow_obs)) {
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
/// `flavor` selects the alphabet: see [`Quoted`].
fn parse_quoted_string(parser: &mut Parser<'_>, flavor: Quoted) -> Result<(), Error> {
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
                    Some(ch) if is_quoted_pair_char(ch, flavor) => {}
                    _ => return Err(parser.error(ErrorKind::InvalidQuotedPair)),
                }
            }
            Some(ch) if is_qtext(ch, flavor) => {
                parser.advance();
            }
            // RFC 5322 FWS: plain WSP or CRLF + WSP (folded whitespace). The
            // envelope grammar has no FWS at all — a space there is qtextSMTP
            // and was taken above, so what reaches here is a tab or a CR, both
            // of which `Quoted::Smtp` must refuse rather than fold.
            Some(ch) if flavor != Quoted::Smtp && (is_wsp(ch) || ch == '\r') => {
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
fn try_quoted_string(parser: &mut Parser<'_>, flavor: Quoted) -> bool {
    if parser.peek() != Some('"') {
        return false;
    }
    let save = parser.save();
    if parse_quoted_string(parser, flavor).is_ok() {
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
    address_literal: AddressLiteral,
) -> Result<(Span, Option<String>), Error> {
    let start = parser.pos;

    // Domain literal: [...]
    if parser.peek() == Some('[') {
        if address_literal == AddressLiteral::Reject {
            return Err(parser.error(ErrorKind::InvalidDomainChar { ch: '[' }));
        }
        parse_domain_literal(parser, address_literal)?;
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

/// Parse domain literal: `[` ... `]`, accepting the RFC 5321 §4.1.3
/// `address-literal` alternatives that `policy` admits.
///
/// Whatever the policy, general RFC 5322 domain literals (arbitrary `dtext`,
/// e.g. `[RFC-5322-domain-literal]`) and malformed IP literals
/// (`[255.255.255]`, `[IPv6:1::2:]`) are syntactically consumed and then
/// rejected with [`ErrorKind::InvalidAddressLiteral`]. That matches the isEmail
/// conformance baseline, which classifies such tokens as RFC 5322-only.
fn parse_domain_literal(parser: &mut Parser<'_>, policy: AddressLiteral) -> Result<(), Error> {
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
                if is_address_literal(content, policy) {
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

/// Returns true if the domain-literal content (the text between `[` and `]`) is
/// an `address-literal` that `policy` admits (RFC 5321 §4.1.3). Uses `core::net`
/// parsers, so it needs no allocator.
fn is_address_literal(content: &str, policy: AddressLiteral) -> bool {
    // Checked before anything is recognised, so the answer honours the policy
    // even though `parse_domain` refuses the '[' before reaching here: a
    // predicate that reports a literal under a policy admitting none would be
    // wrong the moment it gained a second caller.
    if policy == AddressLiteral::Reject {
        return false;
    }
    if ipv6_address_literal(content).is_some() {
        return true;
    }
    // The IPv6v4 forms embed the same `IPv4-address-literal` as the standalone
    // alternative, so under the grammar reading its `Snum` padding is admitted
    // in the tail too. `Ipv6Addr` refuses a padded octet, so the tail is
    // depadded before it sees the address.
    if policy == AddressLiteral::Rfc5321 && ipv6_address_literal_with_padded_tail(content).is_some()
    {
        return true;
    }
    // An `IPv6:`-tagged literal that failed the check above is malformed, not a
    // General-address-literal: RFC 5321 §4.1.3 requires a Standardized-tag to be
    // defined by a Standards-Track RFC, and IPv6 is one, so the tag keeps its own
    // alternative's meaning and cannot be reread as free dcontent.
    if has_ipv6_tag(content) {
        return false;
    }

    match policy {
        // Returned above.
        AddressLiteral::Reject => false,
        AddressLiteral::Routable => content.parse::<core::net::Ipv4Addr>().is_ok(),
        AddressLiteral::Rfc5321 => {
            ipv4_address_literal(content).is_some() || is_general_address_literal(content)
        }
    }
}

/// Whether the literal content carries the `IPv6:` tag, valid address or not.
///
/// The tag is an ABNF string literal, hence case-insensitive (RFC 5234 §2.3):
/// `[ipv6:::1]` and `[IPV6:...]` are equally valid spellings.
fn has_ipv6_tag(content: &str) -> bool {
    content
        .get(..5)
        .is_some_and(|tag| tag.eq_ignore_ascii_case("IPv6:"))
}

/// `IPv6-address-literal = "IPv6:" IPv6-addr` (RFC 5321 §4.1.3).
///
/// Returns the address rather than a verdict: every caller that has to know
/// whether this is an IPv6 literal also, sooner or later, has to know which
/// address it is, and parsing it twice to answer the two questions is a cost
/// with nothing on the other side of it.
pub(crate) fn ipv6_address_literal(content: &str) -> Option<core::net::Ipv6Addr> {
    content
        .get(5..)
        .filter(|_| has_ipv6_tag(content))?
        .parse()
        .ok()
}

/// The longest `IPv6-addr` is `IPv6v4-full`, which is 6 groups of 4 hex digits
/// with separators plus a dotted quad: 45 octets. Rounded up to leave room for
/// the input this rejects rather than truncates.
const MAX_IPV6_ADDR_LEN: usize = 64;

/// The `IPv6:`-tagged IPv6v4 address whose embedded `IPv4-address-literal` is
/// valid `Snum` but zero-padded, if that is what the content is.
///
/// `Ipv6Addr` follows the URI grammar's `dec-octet` (RFC 3986 §3.2.2) and
/// refuses a padded octet, while the mail grammar's `Snum` places no rule on
/// padding, so the tail is rewritten without it and the whole address re-parsed.
/// The rewrite goes to the stack: the address has a known upper bound, and this
/// runs on the parse path.
pub(crate) fn ipv6_address_literal_with_padded_tail(content: &str) -> Option<core::net::Ipv6Addr> {
    let addr = content.get(5..).filter(|_| has_ipv6_tag(content))?;
    // An IPv6v4 form is the only one with a dot, and the tail runs from the last
    // colon to the end.
    let (head, tail) = addr.rsplit_once(':')?;
    ipv4_address_literal(tail)?;

    let mut buf = [0_u8; MAX_IPV6_ADDR_LEN];
    let mut len = 0;
    let mut push = |bytes: &[u8]| -> Option<()> {
        let end = len + bytes.len();
        if end > buf.len() {
            return None;
        }
        buf[len..end].copy_from_slice(bytes);
        len = end;
        Some(())
    };

    push(head.as_bytes())?;
    push(b":")?;
    for (i, octet) in tail.split('.').enumerate() {
        // `ipv4_address_literal` already accepted the tail, so every octet is
        // 1..=3 ASCII digits; trimming zeros can only leave it empty when the
        // octet was all zeros, which is the one case that keeps a digit.
        let trimmed = octet.trim_start_matches('0');
        let digits = if trimmed.is_empty() { "0" } else { trimmed };
        if i > 0 {
            push(b".")?;
        }
        push(digits.as_bytes())?;
    }

    core::str::from_utf8(&buf[..len]).ok()?.parse().ok()
}

/// Whether the literal content names an IP address rather than an opaque
/// system address.
///
/// Normalization needs this distinction: an IP literal carries no case in
/// either part, so folding it keeps two spellings of one address equal, while a
/// `General-address-literal` body is opaque to SMTP and meaningful to the
/// receiving system, so folding it would hand that system a different address.
/// The permissive `Snum` reading is used here on purpose, in the standalone
/// form and in an IPv6v4 tail alike: `[012.0.2.1]` and `[IPv6:::ffff:012.0.2.1]`
/// are IP literals under the grammar even where the routable reading refuses
/// them, and folding their case is a no-op rather than a change of meaning.
/// Leaving either out would classify it as opaque and preserve its case,
/// splitting one address into two under comparison and hashing.
pub(crate) fn is_ip_address_literal(content: &str) -> bool {
    ipv6_address_literal(content).is_some()
        || ipv6_address_literal_with_padded_tail(content).is_some()
        || ipv4_address_literal(content).is_some()
}

/// `IPv4-address-literal = Snum 3("." Snum)`, `Snum = 1*3DIGIT` in 0..=255
/// (RFC 5321 §4.1.3).
///
/// Written out rather than delegated to `core::net::Ipv4Addr`, which rejects a
/// zero-padded octet: that rule comes from the URI grammar's `dec-octet` (RFC
/// 3986 §3.2.2), not from the mail grammar, which places no rule on padding. So
/// `[012.0.2.1]` is inside this grammar and outside `Ipv4Addr`.
///
/// The octets are already decoded on the way to the verdict, so the address is
/// returned rather than thrown away and recomputed by whoever needs it.
pub(crate) fn ipv4_address_literal(content: &str) -> Option<core::net::Ipv4Addr> {
    let mut octets = [0_u8; 4];
    let mut seen = 0;
    for part in content.split('.') {
        if seen == 4 {
            return None;
        }
        // 1*3DIGIT: ASCII digits only, so `+7`, `7_0` and Unicode digits are out.
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // At most 3 ASCII digits, so this cannot overflow u16, and the range
        // check below is what rejects 256..=999.
        let value: u16 = part
            .bytes()
            .fold(0, |acc, b| acc * 10 + u16::from(b - b'0'));
        octets[seen] = u8::try_from(value).ok()?;
        seen += 1;
    }
    (seen == 4).then(|| core::net::Ipv4Addr::from(octets))
}

/// `General-address-literal = Standardized-tag ":" 1*dcontent`, with
/// `Standardized-tag = Ldh-str` and `dcontent = %d33-90 / %d94-126`
/// (RFC 5321 §4.1.3).
///
/// The tag is not checked against the IANA registry: this crate reads addresses,
/// it does not deliver to them, and refusing an unregistered but well-formed tag
/// would fail the document rather than the delivery.
fn is_general_address_literal(content: &str) -> bool {
    let Some((tag, body)) = content.split_once(':') else {
        return false;
    };
    is_ldh_str(tag) && !body.is_empty() && body.bytes().all(is_dcontent)
}

/// `Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig` (RFC 5321 §4.1.2): letters,
/// digits and hyphens, ending in a letter or digit.
fn is_ldh_str(tag: &str) -> bool {
    tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && tag
            .bytes()
            .next_back()
            .is_some_and(|b| b.is_ascii_alphanumeric())
}

/// `dcontent = %d33-90 / %d94-126` (RFC 5321 §4.1.3): printable ASCII except
/// space, `[`, `\`, `]` and DEL.
fn is_dcontent(b: u8) -> bool {
    matches!(b, 33..=90 | 94..=126)
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
/// non-ASCII. [`Quoted::Obsolete`] also accepts obs-qtext (obs-NO-WS-CTL
/// controls); [`Quoted::Smtp`] reads `qtextSMTP` (RFC 5321 §4.1.2) instead,
/// which is the same set plus space, since the envelope grammar has no folding
/// whitespace to confuse a space with.
fn is_qtext(ch: char, flavor: Quoted) -> bool {
    if ch == '"' || ch == '\\' {
        return false;
    }
    match flavor {
        Quoted::Smtp => ch == ' ' || is_printable_ascii(ch) || is_utf8_non_ascii(ch),
        Quoted::Header => is_printable_ascii(ch) || is_utf8_non_ascii(ch),
        Quoted::Obsolete => is_printable_ascii(ch) || is_utf8_non_ascii(ch) || is_obs_no_ws_ctl(ch),
    }
}

/// ctext: printable ASCII except `(`, `)`, `\`, plus UTF-8 non-ASCII.
fn is_ctext(ch: char) -> bool {
    ch != '(' && ch != ')' && ch != '\\' && (is_printable_ascii(ch) || is_utf8_non_ascii(ch))
}

/// Characters valid in a quoted-pair after `\` (RFC 5322 §3.2.1: `quoted-pair =
/// "\" (VCHAR / WSP)`). Non-ASCII is intentionally excluded — RFC 6531 allows
/// UTF-8 directly in qtext, so escaping it is invalid. [`Quoted::Obsolete`]
/// also accepts obs-qp: NUL, CR, LF, and obs-NO-WS-CTL controls.
///
/// [`Quoted::Smtp`] reads `quoted-pairSMTP = %d92 %d32-126` (RFC 5321 §4.1.2),
/// which is `VCHAR / SP` — space but not tab, the one place the envelope
/// alphabet is narrower than the header one here.
fn is_quoted_pair_char(ch: char, flavor: Quoted) -> bool {
    match flavor {
        Quoted::Smtp => ch == ' ' || is_printable_ascii(ch),
        Quoted::Header => is_printable_ascii(ch) || is_wsp(ch),
        Quoted::Obsolete => {
            is_printable_ascii(ch)
                || is_wsp(ch)
                || matches!(ch, '\0' | '\n' | '\r')
                || is_obs_no_ws_ctl(ch)
        }
    }
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
