use crate::ast::group::Group;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_set};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_group(pair: Pair<'_>, context: &mut ParserContext) -> Group {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut expression = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::expression => parse_set!(parse_expression(current, context), children, expression),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    Group {
        span,
        children,
        path,
        expression,
    }
}