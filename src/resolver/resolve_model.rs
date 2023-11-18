use indexmap::indexmap;
use maplit::btreemap;
use crate::ast::model::{Model, ModelResolved};
use crate::ast::reference_space::ReferenceSpace;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_field::{FieldParentType, resolve_field_class, resolve_field_decorators};
use crate::resolver::resolve_handler_group::{resolve_handler_declaration_decorators, resolve_handler_declaration_types};
use crate::resolver::resolve_model_shapes::resolve_model_shapes;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_model_types<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    let actual_availability = context.current_availability();
    *model.actual_availability.borrow_mut() = actual_availability;
    if context.has_examined_default_path(&model.string_path, model.define_availability) {
        context.insert_duplicated_identifier(model.identifier().span);
    }
    context.clear_examined_fields();
    // fields
    for field in model.fields() {
        resolve_field_class(field, FieldParentType::Model, None, None, context);
    }
    model.resolve(ModelResolved {
        enums: indexmap! {},
        shapes: indexmap! {},
    });
    resolve_model_shapes(model, context);
    context.add_examined_default_path(model.string_path.clone(), model.define_availability);
}

pub(super) fn resolve_model_references<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    // handlers
    for handler in model.handlers() {
        resolve_handler_declaration_types(handler, context);
    }
}

pub(super) fn resolve_model_decorators<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    // decorators
    let model_type = Type::ModelObject(Reference::new(model.path.clone(), model.string_path.clone()));
    for decorator in model.decorators() {
        resolve_decorator(decorator, context, &btreemap!{
            Keyword::SelfIdentifier => model_type.clone()
        }, ReferenceSpace::ModelDecorator);
    }
    // fields
    for field in model.fields() {
        resolve_field_decorators(model, field, context);
    }
    // handlers
    for handler in model.handlers() {
        resolve_handler_declaration_decorators(handler, context);
    }
}