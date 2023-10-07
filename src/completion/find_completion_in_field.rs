use crate::ast::field::Field;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_context::CompletionContext;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_decorator::find_completion_in_decorator;

pub(super) fn find_completion_in_field<'a>(schema: &Schema, source: &Source, field: &'a Field, line_col: (usize, usize)) -> Vec<CompletionItem> {
    let mut namespace_path: Vec<_> = field.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    namespace_path.pop();
    for decorator in &field.decorators {
        if decorator.span.contains_line_col(line_col) {
            return find_completion_in_decorator(schema, source, decorator, &namespace_path, line_col, field.resolved().class.reference_type());
        }
    }
    vec![]
}