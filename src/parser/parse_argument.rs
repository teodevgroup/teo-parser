use std::cell::RefCell;
use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::node::Node;
use crate::ast::punctuations::Punctuation;
use crate::{parse_insert_punctuation, parse_container_node_variables, parse_insert, parse_set, parse_set_optional, parse_container_node_variables_cleanup};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_argument_list(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentList {
    parse_container_node_variables!();
    let mut arguments = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::argument => parse_insert!(parse_argument(current, context), arguments),
            Rule::PAREN_OPEN => parse_insert_punctuation!("("),
            Rule::PAREN_CLOSE => parse_insert_punctuation!(")"),
            Rule::COMMA => parse_insert_punctuation!(","),
            Rule::empty_argument => context.insert_error(parse_span(&current), "empty argument"),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!();
    ArgumentList {
        span,
        path,
        children,
        arguments,
    }
}

pub(super) fn parse_argument(pair: Pair<'_>, context: &mut ParserContext) -> Argument {
    parse_container_node_variables!();
    let mut name: Option<usize> = None;
    let mut value: usize = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => parse_set_optional!(parse_identifier(&current), name),
            Rule::expression => parse_set!(parse_expression(current, context), expression),
            Rule::COLON => parse_insert_punctuation!(":"),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!();
    Argument {
        span,
        children,
        path,
        name,
        value,
        resolved: RefCell::new(None),
    }
}
