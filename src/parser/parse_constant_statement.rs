use std::cell::RefCell;
use crate::ast::constant_declaration::ConstantDeclaration;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert_keyword, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_constant_statement(pair: Pair<'_>, context: &ParserContext) -> ConstantDeclaration {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut identifier: usize = 0;
    let mut expression: usize = 0;
    let mut type_expr: Option<usize> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::LET_KEYWORD => parse_insert_keyword!(context, current, children, "let"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::ASSIGN => parse_insert_punctuation!(context, current, children, "="),
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::expression => parse_set!(parse_expression(current, context), children, expression),
            Rule::type_expression => parse_set_optional!(parse_type_expression(current, context), children, type_expr),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    ConstantDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        identifier,
        type_expr,
        expression,
        resolved: RefCell::new(None),
    }
}
