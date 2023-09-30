use crate::ast::generics::{GenericsConstraint, GenericsConstraintItem, GenericsDeclaration};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_generics_declaration(pair: Pair<'_>, context: &mut ParserContext) -> GenericsDeclaration {
    let span = parse_span(&pair);
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifiers.push(parse_identifier(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    GenericsDeclaration { span, identifiers }
}

pub(super) fn parse_generics_constraint(pair: Pair<'_>, context: &mut ParserContext) -> GenericsConstraint {
    let span = parse_span(&pair);
    let mut items = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::generics_constraint_item => items.push(parse_generics_constraint_item(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    GenericsConstraint { span, items }
}

fn parse_generics_constraint_item(pair: Pair<'_>, context: &mut ParserContext) -> GenericsConstraintItem {
    let span = parse_span(&pair);
    let mut identifier = None;
    let mut type_expr = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::type_expression => type_expr = Some(parse_type_expression(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    GenericsConstraintItem { span, identifier: identifier.unwrap(), type_expr: type_expr.unwrap() }
}