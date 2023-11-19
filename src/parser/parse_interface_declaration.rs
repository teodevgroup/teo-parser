use std::cell::RefCell;
use crate::ast::interface::{InterfaceDeclaration, InterfaceDeclarationResolved};
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_keyword, parse_insert_punctuation, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_interface_declaration(pair: Pair<'_>, context: &ParserContext) -> InterfaceDeclaration {
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
    let mut inside_block = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                inside_block = true;
            },
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::DECLARE_KEYWORD => parse_insert_keyword!(context, current, children, "declare"),
            Rule::INTERFACE_KEYWORD => parse_insert_keyword!(context, current, children, "interface"),
            Rule::EXTENDS_KEYWORD => parse_insert_keyword!(context, current, children, "extends"),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::type_expression => parse_insert!(parse_type_expression(current, context), children, extends),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::field_declaration => parse_insert!(parse_field(current, context), children, fields),
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), children),
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
