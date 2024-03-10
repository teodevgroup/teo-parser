use crate::ast::synthesized_shape_declaration::SynthesizedShapeDeclaration;
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_keyword, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::ast::synthesized_shape_field_declaration::SynthesizedShapeFieldDeclaration;
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_field::parse_field;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_partial_field::parse_partial_field;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_synthesized_shape_declaration(pair: Pair<'_>, context: &ParserContext) -> SynthesizedShapeDeclaration {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut identifier = 0;
    let mut static_fields = vec![];
    let mut partial_static_fields = vec![];
    let mut dynamic_fields = vec![];
    let mut inside_block = false;
    let mut builtin = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                inside_block = true;
            },
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::DECLARE_KEYWORD => parse_insert_keyword!(context, current, children, "declare"),
            Rule::BUILTIN_KEYWORD => {
                parse_insert_keyword!(context, current, children, "declare");
                builtin = true;
            },
            Rule::SYNTHESIZED_KEYWORD => parse_insert_keyword!(context, current, children, "synthesized"),
            Rule::SHAPE_KEYWORD => parse_insert_keyword!(context, current, children, "shape"),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::field_declaration => parse_insert!(parse_field(current, context), children, static_fields),
            Rule::partial_field => parse_insert!(parse_partial_field(current, context), children, partial_static_fields),
            Rule::synthesized_shape_field_declaration => parse_insert!(parse_shape_field_declaration(current, context), children, dynamic_fields),
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), children),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    SynthesizedShapeDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        identifier,
        static_fields,
        partial_static_fields,
        dynamic_fields,
        builtin,
    }
}

fn parse_shape_field_declaration(pair: Pair<'_>, context: &ParserContext) -> SynthesizedShapeFieldDeclaration {
    let (
        span,
        path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, availability);
    let mut comment = None;
    let mut decorator_identifier_path = 0;
    let mut optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::DECLARE_KEYWORD => parse_insert_keyword!(context, current, children, "declare"),
            Rule::REQUIRED_KEYWORD => parse_insert_keyword!(context, current, children, "required"),
            Rule::OPTIONAL_KEYWORD => {
                parse_insert_keyword!(context, current, children, "required");
                optional = true;
            }
            Rule::SYNTHESIZED_KEYWORD => parse_insert_keyword!(context, current, children, "synthesized"),
            Rule::FIELD_KEYWORD => parse_insert_keyword!(context, current, children, "field"),
            Rule::WITH_KEYWORD => parse_insert_keyword!(context, current, children, "with"),
            Rule::AT => parse_insert_punctuation!(context, current, children, "@"),
            Rule::identifier_path => parse_set!(parse_identifier_path(current, context), children, decorator_identifier_path),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    SynthesizedShapeFieldDeclaration {
        span,
        path,
        children,
        define_availability,
        actual_availability,
        comment,
        decorator_identifier_path,
        optional,
    }
}