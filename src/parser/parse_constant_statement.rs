use std::cell::RefCell;
use crate::ast::constant::Constant;
use crate::{parse_container_node_variables, parse_set, parse_set_optional};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_constant_statement(pair: Pair<'_>, context: &mut ParserContext) -> Constant {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    
    let mut identifier: usize = 0;
    let mut expression: usize = 0;
    let mut type_expr: Option<usize> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => parse_set!(parse_identifier(&current, context), children, identifier),
            Rule::expression => parse_set!(parse_expression(current, context), children, expression),
            Rule::type_expression => parse_set_optional!(parse_type_expression(current, context), children, type_expr),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Constant {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        identifier,
        type_expr,
        expression,
        resolved: RefCell::new(None),
    }
}
