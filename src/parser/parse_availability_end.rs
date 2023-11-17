use crate::ast::availability_flag_end::AvailabilityFlagEnd;
use crate::parse_node_variables;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::Pair;

pub(super) fn parse_availability_end(pair: Pair<'_>, context: &ParserContext) -> AvailabilityFlagEnd {
    let (span, path) = parse_node_variables!(pair, context);
    context.pop_availability_flag(span);
    AvailabilityFlagEnd {
        span,
        path,
    }
}