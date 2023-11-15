use crate::ast::function_declaration::FunctionDeclaration;
use crate::{parse_container_node_variables, parse_insert_keyword, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_function_declaration(pair: Pair<'_>, context: &mut ParserContext, inside_struct: bool) -> FunctionDeclaration {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut r#static = false;
    let mut identifier = 0;
    let mut generics_declaration = None;
    let mut argument_list_declaration = 0;
    let mut generics_constraint = None;
    let mut return_type = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::PAREN_OPEN => parse_insert_punctuation!(context, current, children, "("),
            Rule::PAREN_CLOSE => parse_insert_punctuation!(context, current, children, ")"),
            Rule::DECLARE_KEYWORD => parse_insert_keyword!(context, current, children, "declare"),
            Rule::FUNCTION_KEYWORD => parse_insert_keyword!(context, current, children, "function"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::STATIC_KEYWORD => {
                parse_insert_keyword!(context, current, children, "static");
                r#static = true;
            },
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::argument_list_declaration => parse_set!(parse_argument_list_declaration(current, context), children, argument_list_declaration),
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, return_type),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    FunctionDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        r#static,
        inside_struct,
        comment,
        identifier,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        return_type,
    }
}
