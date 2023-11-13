use crate::ast::handler::{HandlerDeclaration, HandlerGroupDeclaration, HandlerInputFormat};
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_handler_group_declaration(pair: Pair<'_>, context: &mut ParserContext) -> HandlerGroupDeclaration {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut identifier = 0;
    let mut handler_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::HANDLER_KEYWORD => (),
            Rule::triple_comment_block => parse_set_optional!(parse_comment(current, context), children, comment),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::handler_declaration => parse_insert!(parse_handler_declaration(current, context), children, handler_declarations),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    HandlerGroupDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        identifier,
        handler_declarations,
    }
}

pub(super) fn parse_handler_declaration(pair: Pair<'_>, context: &mut ParserContext) -> HandlerDeclaration {
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
    let mut empty_decorators_spans = vec![];
    let mut identifier = 0;
    let mut input_type = 0;
    let mut output_type = 0;
    let mut input_format: HandlerInputFormat = HandlerInputFormat::Json;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => parse_set_optional!(parse_comment(current, context), children, comment),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::type_expression => if input_type != 0 {
                parse_set!(parse_type_expression(current, context), children, output_type);
            } else {
                parse_set!(parse_type_expression(current, context), children, input_type);
            },
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::HANDLER_KEYWORD => (),
            Rule::decorator => parse_insert!(parse_decorator(current, context), children, decorators),
            Rule::empty_decorator => empty_decorators_spans.push(parse_span(&current)),
            Rule::req_type => if current.as_str() == "form" {
                input_format = HandlerInputFormat::Form
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    HandlerDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        decorators,
        empty_decorators_spans,
        identifier,
        input_type,
        output_type,
        input_format,
    }
}