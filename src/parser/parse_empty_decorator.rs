use crate::ast::empty_decorator::EmptyDecorator;
use crate::parse_node_variables;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::Pair;

pub(super) fn parse_empty_decorator(pair: Pair<'_>, context: &ParserContext) -> EmptyDecorator {
    let ( span, path ) = parse_node_variables!(pair, context);
    EmptyDecorator { span, path }
}