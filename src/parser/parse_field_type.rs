use std::cell::RefCell;
use crate::ast::arity::Arity;
use crate::ast::field_type::FieldType;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_field_type(pair: Pair<'_>, context: &mut ParserContext) -> FieldType {
    let span = parse_span(&pair);
    let mut identifier_path = None;
    let mut generics = vec![];
    let mut item_required = true;
    let mut arity = Arity::Scalar;
    let mut collection_required = true;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => {},
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::field_type_generics => generics = parse_field_type_generics(current, context),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::optionality => if arity == Arity::Scalar { item_required = false; } else { collection_required = false; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    FieldType {
        span,
        identifier_path: identifier_path.unwrap(),
        generics,
        item_required,
        arity,
        collection_required,
        resolved: RefCell::new(None),
    }
}

fn parse_field_type_generics(pair: Pair<'_>, context: &mut ParserContext) -> Vec<FieldType> {
    let mut items = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::field_type => items.push(parse_field_type(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    items
}