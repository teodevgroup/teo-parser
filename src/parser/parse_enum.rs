use crate::ast::identifier::Identifier;
use crate::ast::r#enum::{Enum, EnumMember};
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_enum_declaration(pair: Pair<'_>, context: &mut ParserContext) -> Enum {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut decorators = vec![];
    let mut identifier: Option<Identifier> = None;
    let mut members = vec![];
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::ENUM_KEYWORD | Rule::COLON | Rule::EMPTY_LINES | Rule::BLOCK_CLOSE => {},
            Rule::BLOCK_OPEN => string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name())),
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::item_decorator => decorators.push(parse_decorator(current, context)),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::enum_member_declaration => members.push(parse_enum_member(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_string_path();
    context.pop_parent_id();
    Enum {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        decorators,
        identifier: identifier.unwrap(),
        members,
    }
}

fn parse_enum_member(pair: Pair<'_>, context: &mut ParserContext) -> EnumMember {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut decorators = vec![];
    let mut identifier: Option<Identifier> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::EMPTY_LINES => {},
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::item_decorator => decorators.push(parse_decorator(current, context)),
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    EnumMember {
        span,
        comment,
        decorators,
        identifier: identifier.unwrap(),
    }
}