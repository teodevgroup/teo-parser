use std::cell::RefCell;
use crate::ast::field::Field;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_field(pair: Pair<'_>, context: &mut ParserContext) -> Field {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut decorators = vec![];
    let mut empty_decorators_spans = vec![];
    let mut identifier: Option<Identifier> = None;
    let mut type_expr: Option<TypeExpr> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::EMPTY_LINES | Rule::comment_block | Rule::double_comment_block => {},
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::decorator => decorators.push(parse_decorator(current, context)),
            Rule::empty_decorator => empty_decorators_spans.push(parse_span(&current)),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::type_expression => type_expr = Some(parse_type_expression(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Field {
        span,
        path: context.next_path(),
        string_path: context.next_string_path(identifier.as_ref().unwrap().name()),
        define_availability: context.current_availability_flag(),
        comment,
        decorators,
        empty_decorators_spans,
        identifier: identifier.unwrap(),
        type_expr: type_expr.unwrap(),
        resolved: RefCell::new(None),
    }
}
