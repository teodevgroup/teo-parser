use std::cell::RefCell;
use crate::ast::decorator::Decorator;
use crate::ast::unit::Unit;
use crate::parser::parse_argument::parse_argument_list;
use crate::parser::parse_expression::parse_unit;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_decorator(pair: Pair<'_>, context: &mut ParserContext) -> Decorator {
    let span = parse_span(&pair);
    let mut identifier_path = None;
    let mut argument_list = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::argument_list => argument_list = Some(parse_argument_list(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Decorator {
        span,
        identifier_path: identifier_path.unwrap(),
        argument_list,
        resolved: RefCell::new(None)
    }
}