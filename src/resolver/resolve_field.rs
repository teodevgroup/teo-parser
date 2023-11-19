use maplit::btreemap;
use crate::ast::field::{Field, FieldClass, FieldResolved, ModelPrimitiveFieldSettings, ModelPropertyFieldSettings, ModelRelationSettings};
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::model::Model;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;

pub(super) enum FieldParentType {
    Model,
    Interface,
}

pub(super) fn resolve_field_class<'a>(
    field: &'a Field,
    parent_type: FieldParentType,
    context: &'a ResolverContext<'a>,
) {
    *field.actual_availability.borrow_mut() = context.current_availability();
    match parent_type {
        FieldParentType::Interface => {
            field.resolve(FieldResolved {
                class: FieldClass::InterfaceField,
            });
        }
        FieldParentType::Model => {
            let r#virtual = field.decorators().find(|d| d.identifier_path().names() == ["std", "virtual"] || d.identifier_path().names() == ["virtual"]).is_some();
            let dropped = field.decorators().find(|d| d.identifier_path().names() == ["std", "dropped"] || d.identifier_path().names() == ["dropped"]).is_some();
            let cached = field.decorators().find(|d| d.identifier_path().names() == ["std", "cached"] || d.identifier_path().names() == ["cached"]).is_some();
            let field_class = if let Some(decorator) = field.decorators().find(|d| d.identifier_path().names() == ["std", "relation"] || d.identifier_path().names() == ["relation"]) {
                FieldClass::ModelRelation(ModelRelationSettings {
                    direct: decorator.argument_list().map_or(false, |list| list.arguments().find(|argument| argument.name().map_or(false, |name| name.name() == "fields")).is_some()),
                })
            } else if field.decorators().find(|d| d.identifier_path().names() == ["std", "getter"] || d.identifier_path().names() == ["getter"] || d.identifier_path().names() == ["std", "setter"] || d.identifier_path().names() == ["setter"]).is_some() {
                FieldClass::ModelProperty(ModelPropertyFieldSettings {
                    cached
                })
            } else {
                FieldClass::ModelPrimitiveField(ModelPrimitiveFieldSettings {
                    r#virtual,
                    dropped
                })
            };
            field.resolve(FieldResolved {
                class: field_class,
            });
        }
    }
}

pub(super) fn resolve_field_types<'a>(
    field: &'a Field,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) {
    resolve_type_expr(
        field.type_expr(),
        &if let Some(generics_declaration) = generics_declaration {
            vec![generics_declaration]
        } else {
            vec![]
        },
        &if let Some(generics_constraint) = generics_constraint {
            vec![generics_constraint]
        } else {
            vec![]
        },
        &btreemap! {},
        context,
        field.define_availability
    );
}

pub(super) fn resolve_field_decorators<'a>(
    model: &'a Model,
    field: &'a Field,
    context: &'a ResolverContext<'a>,
) {
    let model_type = Type::ModelObject(Reference::new(model.path.clone(), model.string_path.clone()));

    for decorator in field.decorators() {
        resolve_decorator(decorator, context, &btreemap!{
            Keyword::SelfIdentifier => model_type.clone(),
            Keyword::ThisFieldType => if field.resolved().class.is_model_relation() {
                field.type_expr().resolved().unwrap_optional().unwrap_array().clone()
            } else {
                field.type_expr().resolved().clone()
            },
        }, field.resolved().class.reference_type());
    }
}