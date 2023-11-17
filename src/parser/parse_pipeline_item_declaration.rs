use crate::ast::pipeline_item_declaration::{PipelineItemDeclaration, PipelineItemDeclarationVariant};
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_keyword, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};

use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_pipeline_item_declaration(pair: Pair<'_>, context: &ParserContext) -> PipelineItemDeclaration {
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
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    let mut input_type = None;
    let mut output_type = None;
    let mut variants = vec![];
    let mut inside_block = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::DECLARE_KEYWORD => parse_insert_keyword!(context, current, children, "declare"),
            Rule::PIPELINE_KEYWORD => parse_insert_keyword!(context, current, children, "pipeline"),
            Rule::ITEM_KEYWORD => parse_insert_keyword!(context, current, children, "item"),
            Rule::ARROW => parse_insert_punctuation!(context, current, children, "->"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
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
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::argument_list_declaration => parse_set_optional!(parse_argument_list_declaration(current, context), children, argument_list_declaration),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::pipeline_item_variant_declaration => parse_insert!(parse_pipeline_item_variant_declaration(current, context), children, variants),
            Rule::type_expression => if input_type.is_some() {
                parse_set_optional!(parse_type_expression(current, context), children, output_type);
            } else {
                parse_set_optional!(parse_type_expression(current, context), children, input_type);
            }
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    PipelineItemDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        identifier,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        input_type,
        output_type,
        variants,
    }
}

fn parse_pipeline_item_variant_declaration(pair: Pair<'_>, context: &ParserContext) -> PipelineItemDeclarationVariant {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut comment = None;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    let mut input_type = 0;
    let mut output_type = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::VARIANT_KEYWORD => parse_insert_keyword!(context, current, children, "variant"),
            Rule::ARROW => parse_insert_punctuation!(context, current, children, "->"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::argument_list_declaration => parse_set_optional!(parse_argument_list_declaration(current, context), children, argument_list_declaration),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::type_expression => if input_type != 0 {
                parse_set!(parse_type_expression(current, context), children, output_type);
            } else {
                parse_set!(parse_type_expression(current, context), children, input_type);
            }
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    PipelineItemDeclarationVariant {
        span,
        children,
        path,
        comment,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        input_type,
        output_type,
    }
}
