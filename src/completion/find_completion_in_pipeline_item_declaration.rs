use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list_declaration::find_completion_in_argument_list_declaration;
use crate::traits::info_provider::InfoProvider;

pub(super) fn find_completion_in_pipeline_item_declaration(schema: &Schema, source: &Source, pipeline_item_declaration: &PipelineItemDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if let Some(argument_list_declaration) = pipeline_item_declaration.argument_list_declaration() {
        if argument_list_declaration.span.contains_line_col(line_col) {
            return find_completion_in_argument_list_declaration(schema, source, argument_list_declaration, line_col, &pipeline_item_declaration.generics_declaration().into_iter().collect(), &pipeline_item_declaration.namespace_str_path(), pipeline_item_declaration.define_availability);
        }
    }
    for variant in pipeline_item_declaration.variants() {
        if let Some(argument_list_declaration) = variant.argument_list_declaration() {
            if argument_list_declaration.span.contains_line_col(line_col) {
                return find_completion_in_argument_list_declaration(schema, source, argument_list_declaration, line_col, &pipeline_item_declaration.generics_declaration().into_iter().collect(), &pipeline_item_declaration.namespace_str_path(), pipeline_item_declaration.define_availability);
            }
        }
    }
    vec![]
}

