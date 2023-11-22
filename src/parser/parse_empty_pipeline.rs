use crate::parse_node_variables;
use crate::ast::empty_pipeline::EmptyPipeline;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::Pair;

pub(super) fn parse_empty_pipeline(pair: Pair<'_>, context: &ParserContext) -> EmptyPipeline {
    let ( span, path ) = parse_node_variables!(pair, context);
    EmptyPipeline { span, path }
}