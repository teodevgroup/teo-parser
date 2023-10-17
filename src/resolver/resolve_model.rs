use maplit::btreemap;
use crate::ast::field::FieldClass;
use crate::ast::model::{Model, ModelResolved};
use crate::ast::reference::ReferenceType;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_field::{FieldParentType, resolve_field_class, resolve_field_decorators};
use crate::resolver::resolve_handler_group::{resolve_handler_declaration_decorators, resolve_handler_declaration_types};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_model_info<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    if context.has_examined_default_path(&model.string_path, model.availability) {
        context.insert_duplicated_identifier(model.identifier.span);
    }
    context.clear_examined_fields();
    let mut scalar_fields = vec![];
    let mut scalar_fields_without_virtuals = vec![];
    let mut scalar_fields_and_cached_properties_without_virtuals = vec![];
    let mut direct_relations = vec![];
    let mut relations = vec![];
    // fields
    for field in &model.fields {
        resolve_field_class(field, FieldParentType::Model, None, None, context);
        match field.resolved().class {
            FieldClass::ModelPrimitiveField(settings) => {
                if !settings.dropped {
                    scalar_fields.push(field.name().to_string());
                    if !settings.r#virtual {
                        scalar_fields_without_virtuals.push(field.name().to_string());
                        scalar_fields_and_cached_properties_without_virtuals.push(field.name().to_string());
                    }
                }
            }
            FieldClass::ModelRelation(settings) => {
                if settings.direct {
                    direct_relations.push(field.name().to_string());
                }
                relations.push(field.name().to_string());
            }
            FieldClass::ModelProperty(settings) => {
                if settings.cached {
                    scalar_fields_and_cached_properties_without_virtuals.push(field.name().to_string());
                }
            }
            FieldClass::InterfaceField => {}
            FieldClass::ConfigDeclarationField => {}
        }
    }
    // handlers
    for handler in &model.handlers {
        resolve_handler_declaration_types(handler, context);
    }
    model.resolve(ModelResolved {
        scalar_fields,
        scalar_fields_without_virtuals,
        scalar_fields_and_cached_properties_without_virtuals,
        relations,
        direct_relations,
    });
    context.add_examined_default_path(model.string_path.clone(), model.availability);
}

pub(super) fn resolve_model_decorators<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    // decorators
    let model_type = Type::ModelObject(model.path.clone(), model.string_path.clone());
    for decorator in &model.decorators {
        resolve_decorator(decorator, context, &btreemap!{
            Keyword::SelfIdentifier => &model_type
        }, ReferenceType::ModelDecorator);
    }
    // fields
    for field in &model.fields {
        resolve_field_decorators(model, field, context);
    }
    // handlers
    for handler in &model.handlers {
        resolve_handler_declaration_decorators(handler, context);
    }
}