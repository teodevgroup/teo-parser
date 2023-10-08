use crate::ast::field::{Field, FieldClass, FieldResolved};
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) enum FieldParentType {
    Model,
    Interface,
}

pub(super) fn resolve_field<'a>(
    field: &'a Field,
    parent_type: FieldParentType,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>,
) {
    match parent_type {
        FieldParentType::Interface => {
            field.resolve(FieldResolved { class: FieldClass::InterfaceField });
        }
        FieldParentType::Model => {
            let field_class = if field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "relation"] || d.identifier_path.names() == ["relation"]).is_some() {
                FieldClass::ModelRelation
            } else if field.decorators.iter().find(|d| d.identifier_path.names() == ["std", "getter"] || d.identifier_path.names() == ["getter"] || d.identifier_path.names() == ["std", "setter"] || d.identifier_path.names() == ["setter"]).is_some() {
                FieldClass::ModelProperty
            } else {
                FieldClass::ModelPrimitiveField
            };
            for decorator in &field.decorators {
                resolve_decorator(decorator, context, field_class.reference_type());
            }
            field.resolve(FieldResolved { class: field_class });
        }
    }
    resolve_type_expr(
        &field.type_expr,
        generics_declaration,
        generics_constraint,
        context
    );
}