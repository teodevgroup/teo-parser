use crate::ast::generics::{GenericsConstraint, GenericsConstraintItem, GenericsDeclaration};
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_punctuation, parse_set};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_generics_declaration(pair: Pair<'_>, context: &mut ParserContext) -> GenericsDeclaration {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::CHEVRON_OPEN => parse_insert_punctuation!(context, current, children, "<"),
            Rule::CHEVRON_CLOSE => parse_insert_punctuation!(context, current, children, ">"),
            Rule::COMMA => parse_insert_punctuation!(context, current, children, ","),
            Rule::identifier => parse_insert!(parse_identifier(&current, context), children, identifiers),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    GenericsDeclaration {
        span,
        children,
        path,
        identifiers,
    }
}

pub(super) fn parse_generics_constraint(pair: Pair<'_>, context: &mut ParserContext) -> GenericsConstraint {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut items = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::WHERE => parse_insert_keyword!(context, current, children, "where"),
            Rule::COMMA => parse_insert_punctuation!(context, current, children, ","),
            Rule::generics_constraint_item => parse_insert!(parse_generics_constraint_item(current, context), children, items),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    GenericsConstraint {
        span,
        children,
        path,
        items,
    }
}

fn parse_generics_constraint_item(pair: Pair<'_>, context: &mut ParserContext) -> GenericsConstraintItem {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut identifier = 0;
    let mut type_expr = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::identifier => parse_set!(parse_identifier(&current), children, identifier),
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, type_expr),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    GenericsConstraintItem {
        span,
        children,
        path,
        identifier,
        type_expr,
    }
}