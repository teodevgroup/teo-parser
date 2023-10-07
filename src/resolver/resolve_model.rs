use crate::ast::model::Model;
use crate::ast::reference::ReferenceType;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_field::{FieldParentType, resolve_field};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_model<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    if context.has_examined_default_path(&model.string_path) {
        context.insert_duplicated_identifier(model.identifier.span);
    }
    context.clear_examined_fields();
    // decorators
    for decorator in &model.decorators {
        resolve_decorator(decorator, context, ReferenceType::ModelDecorator);
    }
    // fields
    for field in &model.fields {
        resolve_field(field, FieldParentType::Model, None, None, context);
    }
    context.add_examined_default_path(model.string_path.clone());
}