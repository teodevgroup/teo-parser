use std::cell::RefCell;
use crate::ast::arity::Arity;
use crate::ast::field::Field;
use crate::ast::field_type::FieldType;
use crate::ast::identifier::Identifier;
use crate::ast::model::Model;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_model_declaration(pair: Pair<'_>, context: &mut ParserContext) -> Model {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut decorators = vec![];
    let mut identifier: Option<Identifier> = None;
    let mut fields = vec![];
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::ENUM_KEYWORD | Rule::COLON | Rule::EMPTY_LINES | Rule::BLOCK_CLOSE => {},
            Rule::BLOCK_OPEN => string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name())),
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::item_decorator => decorators.push(parse_decorator(current, context)),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::field_declaration => fields.push(parse_model_field(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_string_path();
    context.pop_parent_id();
    Model {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        decorators,
        identifier: identifier.unwrap(),
        fields,
    }
}

fn parse_model_field(pair: Pair<'_>, context: &mut ParserContext) -> Field {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut decorators = vec![];
    let mut identifier: Option<Identifier> = None;
    let mut field_type: Option<FieldType> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::EMPTY_LINES => {},
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::item_decorator => decorators.push(parse_decorator(current, context)),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::field_type => field_type = Some(parse_model_field_type(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Field {
        span,
        path: context.next_path(),
        string_path: context.next_string_path(identifier.as_ref().unwrap().name()),
        comment,
        decorators,
        identifier: identifier.unwrap(),
        field_type: field_type.unwrap(),
        resolved: RefCell::new(None),
    }
}

fn parse_model_field_type(pair: Pair<'_>, context: &mut ParserContext) -> FieldType {
    let span = parse_span(&pair);
    let mut identifier_path = None;
    let mut item_required = true;
    let mut arity = Arity::Scalar;
    let mut collection_required = true;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => {},
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::optionality => if arity == Arity::Scalar { item_required = false; } else { collection_required = false; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    FieldType {
        span,
        identifier_path: identifier_path.unwrap(),
        item_required,
        arity,
        collection_required,
        resolved: RefCell::new(None),
    }
}