use std::cell::RefCell;
use crate::ast::include_handler_from_template::IncludeHandlerFromTemplate;
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_keyword, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_empty_decorator::parse_empty_decorator;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_include_handler_from_template(pair: Pair<'_>, context: &ParserContext) -> IncludeHandlerFromTemplate {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut as_identifier = None;
    let mut identifier_path = 0;
    let mut decorators = vec![];
    let mut empty_decorators = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::INCLUDE_KEYWORD => parse_insert_keyword!(context, current, children, "include"),
            Rule::HANDLER_KEYWORD => parse_insert_keyword!(context, current, children, "handler"),
            Rule::AS_KEYWORD => parse_insert_keyword!(context, current, children, "as"),
            Rule::decorator => parse_insert!(parse_decorator(current, context), children, decorators),
            Rule::empty_decorator => parse_insert!(parse_empty_decorator(current, context), children, empty_decorators),
            Rule::identifier => parse_set_optional!(parse_identifier(&current, context), children, as_identifier),
            Rule::identifier_path => parse_set!(parse_identifier_path(current, context), children, identifier_path),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    string_path = context.next_parent_string_path(if let Some(identifier) = as_identifier { children.get(&identifier).unwrap().as_identifier().unwrap().name() } else { children.get(&identifier_path).unwrap().as_identifier_path().unwrap().identifiers().last().unwrap().name() });
    parse_container_node_variables_cleanup!(context, named);
    IncludeHandlerFromTemplate {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        as_identifier,
        identifier_path,
        decorators,
        empty_decorators,
        resolved: RefCell::new(None),
    }
}