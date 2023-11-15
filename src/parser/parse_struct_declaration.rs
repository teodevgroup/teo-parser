use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::struct_declaration::StructDeclaration;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_function_declaration::parse_function_declaration;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_struct_declaration(pair: Pair<'_>, context: &mut ParserContext) -> StructDeclaration {
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
    let mut function_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::STRUCT_KEYWORD => (),
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::function_declaration => parse_insert!(parse_function_declaration(current, context, true), children, function_declarations),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    StructDeclaration {
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
        function_declarations,
    }
}
