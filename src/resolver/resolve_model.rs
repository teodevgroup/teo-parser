use crate::ast::model::{Model, ModelResolved};
use crate::ast::reference::ReferenceType;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_field::{FieldParentType, resolve_field_class, resolve_field_decorators};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_model_info<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    if context.has_examined_default_path(&model.string_path) {
        context.insert_duplicated_identifier(model.identifier.span);
    }
    context.clear_examined_fields();
    let mut scalar_fields = vec![];
    let mut scalar_fields_without_virtuals = vec![];
    let mut scalar_fields_and_cached_properties_without_virtuals = vec![];
    // fields
    for field in &model.fields {
        resolve_field_class(field, FieldParentType::Model, None, None, context);
    }
    model.resolve(ModelResolved {
        scalar_fields,
        scalar_fields_without_virtuals,
        scalar_fields_and_cached_properties_without_virtuals,
    });
    context.add_examined_default_path(model.string_path.clone());
}

pub(super) fn resolve_model_decorators<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    // decorators
    for decorator in &model.decorators {
        resolve_decorator(decorator, context, ReferenceType::ModelDecorator);
    }
    // fields
    for field in &model.fields {
        resolve_field_decorators(field, context);
    }
}