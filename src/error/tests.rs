use super::*;

#[test]
fn display_and_accessors_cover_all_kinds() {
    // Every ErrorKind must render a non-empty message, and the accessors
    // must round-trip the kind and position.
    let kinds = [
        ErrorKind::Empty,
        ErrorKind::MissingAtSign,
        ErrorKind::EmptyLocalPart,
        ErrorKind::EmptyDomain,
        ErrorKind::LocalPartTooLong { len: 65 },
        ErrorKind::AddressTooLong { len: 300 },
        ErrorKind::DomainLabelTooLong {
            label: "x".to_string(),
            len: 64,
        },
        ErrorKind::InvalidLocalPartChar { ch: '(' },
        ErrorKind::InvalidDomainChar { ch: '[' },
        ErrorKind::DomainLabelHyphen,
        ErrorKind::DomainNoDot,
        ErrorKind::UnterminatedQuotedString,
        ErrorKind::InvalidQuotedPair,
        ErrorKind::UnterminatedComment,
        ErrorKind::UnterminatedDomainLiteral,
        ErrorKind::InvalidAddressLiteral,
        ErrorKind::IdnaError("boom".to_string()),
        ErrorKind::UnknownTld("zzz".to_string()),
        ErrorKind::Unexpected { ch: '!' },
    ];
    for (pos, kind) in kinds.into_iter().enumerate() {
        let err = Error::new(kind.clone(), pos);
        assert!(!err.to_string().is_empty(), "empty Display for {kind:?}");
        assert_eq!(err.kind(), &kind);
        assert_eq!(err.position(), pos);
    }
}
