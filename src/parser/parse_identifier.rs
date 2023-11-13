use crate::ast::identifier::Identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use super::pest_parser::Pair;

pub(super) fn parse_identifier(pair: &Pair<'_>, context: &mut ParserContext) -> Identifier {
    Identifier {
        span: parse_span(pair),
        path: context.next_path(),
        name: pair.as_str().to_owned(),
    }
}