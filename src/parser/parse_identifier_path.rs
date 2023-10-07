use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_identifier_path(pair: Pair<'_>, context: &mut ParserContext) -> IdentifierPath {
    let mut main_span: Option<Span> = None;
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => {
                let span = parse_span(&current);
                identifiers.push(parse_identifier(&current));
                if let Some(main_span_unwrapped) = main_span {
                    main_span = Some(main_span_unwrapped.merge(&span))
                } else {
                    main_span = Some(span);
                }
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    IdentifierPath {
        span: main_span.unwrap(),
        identifiers,
    }
}