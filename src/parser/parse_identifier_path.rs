use crate::ast::identifier_path::IdentifierPath;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use super::pest_parser::{Pair, Rule};

fn parse_identifier_path(pair: Pair<'_>, context: &mut ParserContext) -> IdentifierPath {
    let span = parse_span(&pair);
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifiers.push(parse_identifier(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    IdentifierPath {
        span,
        identifiers,
    }
}