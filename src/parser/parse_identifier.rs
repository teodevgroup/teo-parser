use crate::ast::identifier::Identifier;
use crate::parser::parse_span::parse_span;
use super::pest_parser::Pair;

pub(super) fn parse_identifier(pair: &Pair<'_>) -> Identifier {
    Identifier {
        name: pair.as_str().to_owned(),
        span: parse_span(pair),
    }
}