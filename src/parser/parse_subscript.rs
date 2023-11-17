use std::str::FromStr;
use crate::ast::int_subscript::IntSubscript;
use crate::ast::subscript::Subscript;
use crate::{parse_container_node_variables, parse_insert_punctuation, parse_node_variables, parse_set};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_subscript(pair: Pair<'_>, context: &ParserContext) -> Subscript {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut expression = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BRACKET_OPEN => parse_insert_punctuation!(context, current, children, "["),
            Rule::BRACKET_CLOSE => parse_insert_punctuation!(context, current, children, "]"),
            Rule::expression => parse_set!(parse_expression(current, context), children, expression),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Subscript { span, children, path, expression }
}

pub(super) fn parse_int_subscript(pair: Pair<'_>, context: &ParserContext) -> IntSubscript {
    let (span, path) = parse_node_variables!(pair, context);
    //let mut index = 0;
    // for current in pair.into_inner() {
    //     match current.as_rule() {
    //         Rule::DOT => (),
    //         Rule::numeric_literal => index = usize::from_str(current.as_str()).unwrap_or(0),
    //     }
    // }
    let index = usize::from_str(pair.as_str()).unwrap_or(0);
    IntSubscript { span, path, index, index_string: index.to_string() }
}