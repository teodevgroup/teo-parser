use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert_keyword, parse_set};
use crate::ast::type_as_value_expression::TypeAsValueExpression;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_type_as_value_expression(pair: Pair<'_>, context: &ParserContext) -> TypeAsValueExpression {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut type_expr = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::TYPE_KEYWORD => parse_insert_keyword!(context, current, children, "type"),
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, type_expr),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    TypeAsValueExpression {
        span,
        path,
        children,
        type_expr,
    }
}
