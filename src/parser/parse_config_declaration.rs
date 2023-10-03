use crate::ast::comment::Comment;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_config_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ConfigDeclaration {
    let span = parse_span(&pair);
    let mut comment: Option<Comment> = None;
    let mut identifier: Option<Identifier> = None;
    let mut fields: Vec<Field> = vec![];
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN => string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name())),
            Rule::BLOCK_CLOSE | Rule::EMPTY_LINES => (),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::field_declaration => fields.push(parse_field(current, context)),
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::BLOCK_LEVEL_CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    if context.current_string_path() != vec!["std".to_owned()] {
        context.insert_error(identifier.as_ref().unwrap().span, "ConfigError: Invalid config declaration, config declarations are builtin thus cannot be declared")
    }
    context.pop_parent_id();
    context.pop_string_path();
    ConfigDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        identifier: identifier.unwrap(),
        fields,
    }
}
