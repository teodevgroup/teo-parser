use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::identifier::Identifier;
use crate::ast::model::Model;
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_handler_group::parse_handler_declaration;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_model_declaration(pair: Pair<'_>, context: &mut ParserContext) -> Model {
    let span = parse_span(&pair);
    let mut parsing_fields = false;
    let mut comment = None;
    let mut decorators = vec![];
    let mut empty_decorator_spans = vec![];
    let mut empty_field_decorator_spans = vec![];
    let mut unattached_field_decorators = vec![];
    let mut identifier: Option<Identifier> = None;
    let mut fields = vec![];
    let mut handlers = vec![];
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::MODEL_KEYWORD | Rule::COLON | Rule::EMPTY_LINES | Rule::BLOCK_CLOSE | Rule::double_comment_block | Rule::comment_block => {},
            Rule::BLOCK_OPEN => {
                string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name()));
                parsing_fields = true;
            },
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::decorator => if parsing_fields {
                unattached_field_decorators.push(parse_decorator(current, context));
            } else {
                decorators.push(parse_decorator(current, context));
            },
            Rule::empty_decorator => if parsing_fields {
                empty_field_decorator_spans.push(parse_span(&current));
            } else {
                empty_decorator_spans.push(parse_span(&current));
            },
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::field_declaration => fields.push(parse_field(current, context)),
            Rule::handler_declaration => handlers.push(parse_handler_declaration(current, context)),
            Rule::availability_start => parse_availability_flag(current, context),
            Rule::availability_end => parse_availability_end(current, context),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_string_path();
    context.pop_parent_id();
    Model {
        span,
        path,
        string_path: string_path.unwrap(),
        define_availability: context.current_availability_flag(),
        actual_availability: RefCell::new(Availability::none()),
        comment,
        decorators,
        empty_decorator_spans,
        identifier: identifier.unwrap(),
        fields,
        handlers,
        empty_field_decorator_spans,
        unattached_field_decorators,
        resolved: RefCell::new(None),
    }
}
