use std::cell::RefCell;
use crate::ast::interface::{InterfaceDeclaration, InterfaceDeclarationResolved};
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_interface_declaration(pair: Pair<'_>, context: &mut ParserContext) -> InterfaceDeclaration {
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
    let mut generics_declaration = None;
    let mut generics_constraint = None;
    let mut extends = vec![];
    let mut fields = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => parse_set_optional!(parse_comment(current, context), children, comment),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::type_expression => parse_insert!(parse_type_expression(current, context), children, extends),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::field_declaration => parse_insert!(parse_field(current, context), children, fields),
            Rule::BLOCK_OPEN | Rule::COLON | Rule::BLOCK_CLOSE | Rule::EMPTY_LINES | Rule::WHITESPACE | Rule::INTERFACE_KEYWORD => (),
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), chilren),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    InterfaceDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        identifier,
        generics_declaration,
        generics_constraint,
        extends,
        fields,
        resolved: RefCell::new(Some(InterfaceDeclarationResolved::new())),
    }
}
