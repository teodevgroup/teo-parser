use std::str::FromStr;
use crate::ast::expression::Expression;
use crate::ast::int_subscript::IntSubscript;
use crate::ast::subscript::Subscript;
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_subscript(pair: Pair<'_>, context: &mut ParserContext) -> Subscript {
    let span = parse_span(&pair);
    let mut expression = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::expression => expression = Some(parse_expression(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Subscript { span, expression: Box::new(Expression::new(expression.unwrap())) }
}

pub(super) fn parse_int_subscript(pair: Pair<'_>, context: &mut ParserContext) -> IntSubscript {
    let span = parse_span(&pair);
    let index = if let Ok(index) = usize::from_str(pair.as_str()) {
        index
    } else {
        0
    };
    IntSubscript { span, index }
}