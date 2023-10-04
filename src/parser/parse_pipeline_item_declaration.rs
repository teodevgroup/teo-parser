use crate::ast::pipeline_item_declaration::{PipelineItemDeclaration, PipelineItemDeclarationVariant};
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_pipeline_item_declaration(pair: Pair<'_>, context: &mut ParserContext) -> PipelineItemDeclaration {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut comment = None;
    let mut identifier = None;
    let mut string_path = None;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    let mut input_type = None;
    let mut output_type = None;
    let mut variants = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::comment_block => (),
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::generics_declaration => generics_declaration = Some(parse_generics_declaration(current, context)),
            Rule::argument_list_declaration => argument_list_declaration = Some(parse_argument_list_declaration(current, context)),
            Rule::generics_constraint => generics_constraint = Some(parse_generics_constraint(current, context)),
            Rule::pipeline_item_variant_declaration => variants.push(parse_pipeline_item_variant_declaration(current, context)),
            Rule::type_expression => if input_type.is_some() {
                output_type = Some(parse_type_expression(current, context));
            } else {
                input_type = Some(parse_type_expression(current, context));
            }
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    PipelineItemDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        identifier: identifier.unwrap(),
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        variants,
        input_type,
        output_type,
    }
}

fn parse_pipeline_item_variant_declaration(pair: Pair<'_>, context: &mut ParserContext) -> PipelineItemDeclarationVariant {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    let mut input_type = None;
    let mut output_type = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::generics_declaration => generics_declaration = Some(parse_generics_declaration(current, context)),
            Rule::argument_list_declaration => argument_list_declaration = Some(parse_argument_list_declaration(current, context)),
            Rule::generics_constraint => generics_constraint = Some(parse_generics_constraint(current, context)),
            Rule::type_expression => if input_type.is_some() {
                output_type = Some(parse_type_expression(current, context));
            } else {
                input_type = Some(parse_type_expression(current, context));
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    PipelineItemDeclarationVariant {
        span,
        comment,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        input_type: input_type.unwrap(),
        output_type: output_type.unwrap(),
    }
}
