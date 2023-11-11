use crate::ast::field::{Field, FieldClass};
use crate::ast::generics::GenericsDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_decorator::{find_completion_in_decorator, find_completion_in_empty_decorator};
use crate::completion::find_completion_in_type_expr::{find_completion_in_type_expr, TypeExprFilter};
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;

pub(super) fn find_completion_in_field<'a>(schema: &Schema, source: &Source, field: &'a Field, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>) -> Vec<CompletionItem> {
    let mut namespace_path: Vec<_> = field.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    namespace_path.pop();
    for decorator in &field.decorators {
        if decorator.span.contains_line_col(line_col) {
            return find_completion_in_decorator(schema, source, decorator, &namespace_path, line_col, field.resolved().class.reference_type(), field.availability());
        }
    }
    for empty_decorator_span in &field.empty_decorators_spans {
        if empty_decorator_span.contains_line_col(line_col) {
            return find_completion_in_empty_decorator(schema, source, &namespace_path, field.resolved().class.reference_type(), field.availability());
        }
    }
    if field.type_expr.span().contains_line_col(line_col) {
        return find_completion_in_type_expr(schema, source, &field.type_expr, line_col, &field.namespace_str_path(), generics, field_class_to_type_expr_filter(field.resolved().class), field.availability());
    }
    vec![]
}

fn field_class_to_type_expr_filter(class: FieldClass) -> TypeExprFilter {
    match class {
        FieldClass::ModelPrimitiveField(_) | FieldClass::ModelProperty(_) | FieldClass::ModelRelation(_) => TypeExprFilter::Model,
        _ => TypeExprFilter::None,
    }
}