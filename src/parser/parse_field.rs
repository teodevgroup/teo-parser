use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::field::Field;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_field(pair: Pair<'_>, context: &mut ParserContext) -> Field {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut decorators = vec![];
    let mut empty_decorator_spans = vec![];
    let mut identifier = 0;
    let mut type_expr = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::EMPTY_LINES | Rule::comment_block | Rule::double_comment_block => {},
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::decorator => parse_insert!(parse_decorator(current, context), children, decorators),
            Rule::empty_decorator => empty_decorator_spans.push(parse_span(&current)),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, type_expr),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    Field {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        decorators,
        empty_decorator_spans,
        identifier,
        type_expr,
        resolved: RefCell::new(None),
    }
}
