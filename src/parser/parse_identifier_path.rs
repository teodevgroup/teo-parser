use std::collections::BTreeMap;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;
use crate::parse_insert_punctuation;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_identifier_path(pair: Pair<'_>, context: &mut ParserContext) -> IdentifierPath {
    let path = context.next_parent_path();
    let mut children = BTreeMap::new();
    let mut main_span: Option<Span> = None;
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::DOT => parse_insert_punctuation!(context, current, children, "."),
            Rule::identifier => {
                let span = parse_span(&current);
                let identifier = parse_identifier(&current, context);
                identifiers.push(identifier.id());
                children.insert(identifier.id(), identifier.into());
                if let Some(main_span_unwrapped) = main_span {
                    main_span = Some(main_span_unwrapped.merge(&span))
                } else {
                    main_span = Some(span);
                }
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    IdentifierPath {
        span: main_span.unwrap(),
        path,
        children,
        identifiers,
    }
}