use crate::ast::pipeline::Pipeline;
use crate::{parse_container_node_variables, parse_set};
use crate::parser::parse_expression::parse_unit;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_pipeline(pair: Pair<'_>, context: &mut ParserContext) -> Pipeline {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut unit = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier_unit => parse_set!(parse_unit(current, context), children, unit),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Pipeline {
        span,
        children,
        path,
        unit,
    }
}