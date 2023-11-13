use crate::ast::argument_declaration::{ArgumentDeclaration};
use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::{parse_insert_punctuation, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_set};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_argument_list_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentListDeclaration {
    let (span, path, mut children) = parse_container_node_variables!(pair, context);
    let mut argument_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::PAREN_OPEN => parse_insert_punctuation!(context, current, children, "("),
            Rule::PAREN_CLOSE => parse_insert_punctuation!(context, current, children, ")"),
            Rule::argument_declaration => parse_insert!(parse_argument_declaration(current, context), children, argument_declarations),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    ArgumentListDeclaration {
        span,
        path,
        children,
        argument_declarations,
    }
}

fn parse_argument_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentDeclaration {
    let (span, path, mut children) = parse_container_node_variables!(pair, context);
    let mut name = 0;
    let mut name_optional = false;
    let mut type_expr = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => parse_set!(parse_identifier(&current), children, name),
            Rule::OPTIONAL => name_optional = true,
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, type_expr),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    ArgumentDeclaration {
        span,
        path,
        children,
        name,
        name_optional,
        type_expr,
    }
}