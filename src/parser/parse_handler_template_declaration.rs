use crate::ast::handler_template_declaration::HandlerTemplateDeclaration;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert_keyword, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::ast::handler::HandlerInputFormat;
use crate::ast::include_handler_from_template::IncludeHandlerFromTemplate;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_handler_template_declaration(pair: Pair<'_>, context: &ParserContext) -> HandlerTemplateDeclaration {
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
    let mut input_format = HandlerInputFormat::Json;
    let mut nonapi = false;
    let mut decorators = vec![];
    let mut empty_decorators = vec![];
    let mut input_type = None;
    let mut output_type = 0;
    let mut inside_paren = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::PAREN_OPEN => {
                inside_paren = true;
                parse_insert_punctuation!(context, current, children, "(");
            },
            Rule::PAREN_CLOSE => {
                inside_paren = false;
                parse_insert_punctuation!(context, current, children, ")");
            },
            Rule::DECLARE_KEYWORD => parse_insert_keyword!(context, current, children, "declare"),
            Rule::HANDLER_KEYWORD => parse_insert_keyword!(context, current, children, "handler"),
            Rule::TEMPLATE_KEYWORD => parse_insert_keyword!(context, current, children, "template"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::type_expression => if !inside_paren {
                parse_set!(parse_type_expression(current, context), children, output_type);
            } else {
                parse_set_optional!(parse_type_expression(current, context), children, input_type);
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    HandlerTemplateDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        identifier,
        input_type,
        output_type,
        input_format,
        nonapi,
        decorators,
        empty_decorators,
    }
}