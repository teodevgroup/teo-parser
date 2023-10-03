use std::cell::RefCell;
use crate::ast::action::{ActionDeclaration, ActionGroupDeclaration, ActionInputFormat};
use crate::ast::r#type::TypeExpr;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_action_group_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ActionGroupDeclaration {
    let span = parse_span(&pair);
    let path = context.next_parent_path();
    let mut string_path = None;
    let mut comment = None;
    let mut identifier = None;
    let mut action_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN | Rule::COLON | Rule::BLOCK_CLOSE => (),
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::action_declaration => action_declarations.push(parse_action_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    ActionGroupDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        identifier: identifier.unwrap(),
        action_declarations,
    }
}

fn parse_action_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ActionDeclaration {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut string_path = None;
    let mut comment = None;
    let mut identifier = None;
    let mut input_type: Option<TypeExpr> = None;
    let mut output_type: Option<TypeExpr> = None;
    let mut input_format: ActionInputFormat = ActionInputFormat::Json;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::type_expression => if input_type.is_some() {
                output_type = Some(parse_type_expression(current, context));
            } else {
                input_type = Some(parse_type_expression(current, context));
            },
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE => (),
            Rule::req_type => if current.as_str() == "form" {
                input_format = ActionInputFormat::Form
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ActionDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        identifier: identifier.unwrap(),
        input_type: input_type.unwrap(),
        output_type: output_type.unwrap(),
        input_format,
        resolved: RefCell::new(None),
    }
}