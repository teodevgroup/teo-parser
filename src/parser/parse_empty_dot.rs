use crate::ast::empty_dot::EmptyDot;
use crate::parse_node_variables;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::Pair;

pub(super) fn parse_empty_dot(pair: Pair<'_>, context: &ParserContext) -> EmptyDot {
    let ( span, path ) = parse_node_variables!(pair, context);
    EmptyDot { span, path }
}