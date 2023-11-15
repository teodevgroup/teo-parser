use std::cell::RefCell;
use crate::ast::model::Model;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_punctuation, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_handler_group::parse_handler_declaration;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_model_declaration(pair: Pair<'_>, context: &mut ParserContext) -> Model {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut parsing_fields = false;
    let mut comment = None;
    let mut decorators = vec![];
    let mut empty_decorator_spans = vec![];
    let mut empty_field_decorator_spans = vec![];
    let mut unattached_field_decorators = vec![];
    let mut identifier = 0;
    let mut fields = vec![];
    let mut handlers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::MODEL_KEYWORD | Rule::COLON | Rule::EMPTY_LINES | Rule::BLOCK_CLOSE | Rule::double_comment_block | Rule::comment_block => {},
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                parsing_fields = true;
            },
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::decorator => if parsing_fields {
                unattached_field_decorators.push(parse_decorator(current, context));
            } else {
                parse_insert!(parse_decorator(current, context), children, decorators);
            },
            Rule::empty_decorator => if parsing_fields {
                empty_field_decorator_spans.push(parse_span(&current));
            } else {
                empty_decorator_spans.push(parse_span(&current));
            },
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::field_declaration => parse_insert!(parse_field(current, context), children, fields),
            Rule::handler_declaration => parse_insert!(parse_handler_declaration(current, context), children, handlers),
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), chilren),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    Model {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        decorators,
        empty_decorator_spans,
        identifier,
        fields,
        empty_field_decorator_spans,
        unattached_field_decorators,
        handlers,
        resolved: RefCell::new(None),
    }
}
