use crate::ast::field::{Field, FieldClass, FieldResolved, ModelPrimitiveFieldSettings, ModelPropertyFieldSettings};
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) enum FieldParentType {
    Model,
    Interface,
}

pub(super) fn resolve_field_class<'a>(
    field: &'a Field,
    parent_type: FieldParentType,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>,
) {
    match parent_type {
        FieldParentType::Interface => {
            field.resolve(FieldResolved {
                class: FieldClass::InterfaceField,
            });
        }
        FieldParentType::Model => {
            let r#virtual = field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "virtual"] || d.identifier_path.names() == ["virtual"]).is_some();
            let dropped = field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "dropped"] || d.identifier_path.names() == ["dropped"]).is_some();
            let cached = field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "cached"] || d.identifier_path.names() == ["cached"]).is_some();
            let field_class = if field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "relation"] || d.identifier_path.names() == ["relation"]).is_some() {
                FieldClass::ModelRelation
            } else if field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "getter"] || d.identifier_path.names() == ["getter"] || d.identifier_path.names() == ["std", "setter"] || d.identifier_path.names() == ["setter"]).is_some() {
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
            for decorator in &field.decorators {
                resolve_decorator(decorator, context, field_class.reference_type());
            }
        }
    }
    resolve_type_expr(
        &field.type_expr,
        generics_declaration,
        generics_constraint,
        context
    );
}

pub(super) fn resolve_field_decorators<'a>(
    field: &'a Field,
    context: &'a ResolverContext<'a>,
) {
    for decorator in &field.decorators {
        resolve_decorator(decorator, context, field.resolved().class.reference_type());
    }
}