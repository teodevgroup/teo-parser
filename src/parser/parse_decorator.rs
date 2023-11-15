use std::cell::RefCell;
use crate::ast::decorator::Decorator;
use crate::{parse_container_node_variables, parse_set, parse_set_optional};
use crate::parser::parse_argument::parse_argument_list;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_decorator(pair: Pair<'_>, context: &mut ParserContext) -> Decorator {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut identifier_path = 0;
    let mut argument_list = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier_path => parse_set!(parse_identifier_path(current, context), children, identifier_path),
            Rule::argument_list => parse_set_optional!(parse_argument_list(current, context), children, argument_list),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Decorator {
        span,
        children,
        path,
        identifier_path,
        argument_list,
        resolved: RefCell::new(None),
    }
}