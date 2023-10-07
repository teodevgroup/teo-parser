use crate::ast::model::Model;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_context::CompletionContext;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_decorator::find_completion_in_decorator;
use crate::completion::find_completion_in_field::find_completion_in_field;

pub(super) fn find_completion_in_model(schema: &Schema, source: &Source, model: &Model, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for field in &model.fields {
        if field.span.contains_line_col(line_col) {
            return find_completion_in_field(schema, source, field, line_col);
        }
    }
    let mut namespace_path: Vec<_> = model.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    for decorator in &model.decorators {
        if decorator.span.contains_line_col(line_col) {
            return find_completion_in_decorator(schema, source, decorator, &namespace_path, line_col, ReferenceType::ModelDecorator);
        }
    }
    vec![]
}
