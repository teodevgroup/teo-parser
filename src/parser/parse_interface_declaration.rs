use crate::ast::generics_declaration::GenericsDeclaration;
use crate::ast::generics_extending::InterfaceExtending;
use crate::ast::interface::{InterfaceDeclaration, InterfaceField, InterfaceItem};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_interface_declaration(pair: Pair<'_>, context: &mut ParserContext) -> InterfaceDeclaration {
    let span = parse_span(&pair);
    let mut identifier = None;
    let mut generics_declaration = None;
    let mut extends: Vec<InterfaceExtending> = vec![];
    let mut items: Vec<InterfaceItem> = vec![];
    let path = context.next_parent_path();
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                context.push_string_path(identifier.as_ref().unwrap().name());
            },
            Rule::generics_declaration => generics_declaration = Some(parse_generics_declaration(current, context)),
            Rule::interface_extending => extends.push(parse_interface_extending(current, context)),
            Rule::interface_item => items.push(parse_interface_field(current, context)),
            _ => (),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    InterfaceDeclaration {
        span,
        path,
        string_path,
        identifier: identifier.unwrap(),
        generics_declaration,
        extends,
        items,
    }
}

fn parse_generics_declaration(pair: Pair<'_>, context: &mut ParserContext) -> GenericsDeclaration {
    let span = parse_span(&pair);
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifiers.push(parse_identifier(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    GenericsDeclaration { span, items }
}

fn parse_interface_extending(pair: Pair<'_>, context: &mut ParserContext) -> InterfaceExtending {
    let span = parse_span(&pair);
    let mut identifier_path = None;
    let mut items = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::interface_extending_generics => items = parse_interface_extending_generics(current, context),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    InterfaceExtending {
        span, identifier_path: identifier_path.unwrap(), items,
    }
}

fn parse_interface_extending_generics(pair: Pair<'_>, context: &mut ParserContext) -> Vec<InterfaceExtending> {
    let mut extendings = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::interface_extending => extendings.push(parse_interface_extending(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    extendings
}

fn parse_interface_field(pair: Pair<'_>, context: &mut ParserContext) -> InterfaceField {

}