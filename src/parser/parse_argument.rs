use std::cell::RefCell;


use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;


use crate::{parse_insert_punctuation, parse_container_node_variables, parse_insert, parse_set, parse_set_optional, parse_container_node_variables_cleanup};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_partial_argument::parse_partial_argument;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};


pub(super) fn parse_argument_list(pair: Pair<'_>, context: &ParserContext) -> ArgumentList {
    let (span, path, mut children) = parse_container_node_variables!(pair, context);
    let mut arguments = vec![];
    let mut partial_arguments = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::argument => parse_insert!(parse_argument(current, context), children, arguments),
            Rule::partial_argument => parse_insert!(parse_partial_argument(current, context), children, partial_arguments),
            Rule::PAREN_OPEN => parse_insert_punctuation!(context, current, children, "("),
            Rule::PAREN_CLOSE => parse_insert_punctuation!(context, current, children, ")"),
            Rule::COMMA => parse_insert_punctuation!(context, current, children, ","),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    ArgumentList {
        span,
        path,
        children,
        arguments,
        partial_arguments,
    }
}

pub(super) fn parse_argument(pair: Pair<'_>, context: &ParserContext) -> Argument {
    let (span, path, mut children) = parse_container_node_variables!(pair, context);
    let mut name: Option<usize> = None;
    let mut value: usize = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => parse_set_optional!(parse_identifier(&current, context), children, name),
            Rule::expression => parse_set!(parse_expression(current, context), children, value),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    Argument {
        span,
        children,
        path,
        name,
        value,
        resolved: RefCell::new(None),
    }
}
