use crate::ast::identifier::Identifier;
use crate::ast::model::Model;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_identifier::parse_identifier;
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
            Rule::MODEL_KEYWORD | Rule::COLON | Rule::EMPTY_LINES | Rule::BLOCK_CLOSE => {},
            Rule::BLOCK_OPEN => string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name())),
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::item_decorator => decorators.push(parse_decorator(current, context)),
            Rule::empty_item_decorator => (),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::field_declaration => fields.push(parse_field(current, context)),
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
