use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::Pair;

pub(super) fn parse_availability_end(pair: Pair<'_>, context: &mut ParserContext) {
    let span = parse_span(&pair);
    context.pop_availability_flag(span);
}