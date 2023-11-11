use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::handler::{HandlerDeclaration, HandlerGroupDeclaration, HandlerInputFormat};
use crate::ast::type_expr::TypeExpr;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_handler_group_declaration(pair: Pair<'_>, context: &mut ParserContext) -> HandlerGroupDeclaration {
    let span = parse_span(&pair);
    let path = context.next_parent_path();
    let mut string_path = None;
    let mut comment = None;
    let mut identifier = None;
    let mut handler_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::HANDLER_KEYWORD => (),
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::handler_declaration => handler_declarations.push(parse_handler_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    HandlerGroupDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        identifier: identifier.unwrap(),
        handler_declarations,
        define_availability: context.current_availability_flag(),
        actual_availability: RefCell::new(Availability::none()),
    }
}

pub(super) fn parse_handler_declaration(pair: Pair<'_>, context: &mut ParserContext) -> HandlerDeclaration {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut string_path = None;
    let mut comment = None;
    let mut decorators = vec![];
    let mut empty_decorators_spans = vec![];
    let mut identifier = None;
    let mut input_type: Option<TypeExpr> = None;
    let mut output_type: Option<TypeExpr> = None;
    let mut input_format: HandlerInputFormat = HandlerInputFormat::Json;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::type_expression => if input_type.is_some() {
                output_type = Some(parse_type_expression(current, context));
            } else {
                input_type = Some(parse_type_expression(current, context));
            },
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::HANDLER_KEYWORD => (),
            Rule::decorator => decorators.push(parse_decorator(current, context)),
            Rule::empty_decorator => empty_decorators_spans.push(parse_span(&current)),
            Rule::req_type => if current.as_str() == "form" {
                input_format = HandlerInputFormat::Form
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    HandlerDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        decorators,
        empty_decorators_spans,
        identifier: identifier.unwrap(),
        input_type: input_type.unwrap(),
        output_type: output_type.unwrap(),
        input_format,
        define_availability: context.current_availability_flag(),
        actual_availability: RefCell::new(Availability::none()),
    }
}