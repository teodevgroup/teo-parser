use std::cell::RefCell;
use crate::ast::field::Field;
use crate::ast::field_type::FieldType;
use crate::ast::identifier::Identifier;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type::parse_field_type;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_field(pair: Pair<'_>, context: &mut ParserContext) -> Field {
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
            Rule::field_type => field_type = Some(parse_field_type(current, context)),
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
