use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list_declaration::jump_to_definition_in_argument_list_declaration;
use crate::definition::jump_to_definition_in_type_expr::jump_to_definition_in_type_expr_kind;

pub(super) fn jump_to_definition_in_pipeline_item_declaration(schema: &Schema, source: &Source, pipeline_item_declaration: &PipelineItemDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = pipeline_item_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = pipeline_item_declaration.availability;
    if let Some(argument_list_declaration) = &pipeline_item_declaration.argument_list_declaration {
        if argument_list_declaration.span.contains_line_col(line_col) {
            return jump_to_definition_in_argument_list_declaration(
                schema,
                source,
                argument_list_declaration,
                &pipeline_item_declaration.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                &namespace_path,
                line_col,
                availability
            );
        }
    }
    if let Some(input_type) = &pipeline_item_declaration.input_type {
        if input_type.span().contains_line_col(line_col) {
            return jump_to_definition_in_type_expr_kind(
                schema,
                source,
                &input_type.kind,
                &namespace_path,
                line_col,
                &pipeline_item_declaration.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                availability
            );
        }
    }
    if let Some(output_type) = &pipeline_item_declaration.output_type {
        if output_type.span().contains_line_col(line_col) {
            return jump_to_definition_in_type_expr_kind(
                schema,
                source,
                &output_type.kind,
                &namespace_path,
                line_col,
                &pipeline_item_declaration.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                availability
            );
        }
    }
    for variant in &pipeline_item_declaration.variants {
        if let Some(argument_list_declaration) = &variant.argument_list_declaration {
            if argument_list_declaration.span.contains_line_col(line_col) {
                return jump_to_definition_in_argument_list_declaration(
                    schema,
                    source,
                    argument_list_declaration,
                    &variant.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                    &namespace_path,
                    line_col,
                    availability
                );
            }
        }

        if variant.input_type.span().contains_line_col(line_col) {
            return jump_to_definition_in_type_expr_kind(
                schema,
                source,
                &variant.input_type.kind,
                &namespace_path,
                line_col,
                &variant.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                availability
            );
        }
        if variant.output_type.span().contains_line_col(line_col) {
            return jump_to_definition_in_type_expr_kind(
                schema,
                source,
                &variant.output_type.kind,
                &namespace_path,
                line_col,
                &variant.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                availability
            );
        }
    }
    vec![]
}