use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_pipeline_item_declaration(schema: &Schema, source: &Source, pipeline_item_declaration: &PipelineItemDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}