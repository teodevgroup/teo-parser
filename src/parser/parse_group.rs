use std::cell::RefCell;
use crate::ast::expression::Expression;
use crate::ast::group::Group;
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_group(pair: Pair<'_>, context: &mut ParserContext) -> Group {
    let span = parse_span(&pair);
    let mut expression = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::expression => expression = Some(parse_expression(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Group { span, expression: Box::new(Expression { kind: expression.unwrap(), resolved: RefCell::new(None) }) }
}