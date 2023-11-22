use maplit::btreemap;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::field::{FieldClass, FieldResolved};
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_config_declaration_types<'a>(config_declaration: &'a ConfigDeclaration, context: &'a ResolverContext<'a>) {
    for partial_field in config_declaration.partial_fields() {
        context.insert_diagnostics_error(partial_field.span, "partial field");
    }
    for field in config_declaration.fields() {
        *field.actual_availability.borrow_mut() = context.current_availability();
        resolve_type_expr(field.type_expr(), &vec![], &vec![], &btreemap! {}, context, context.current_availability());
        field.resolve(FieldResolved {
            class: FieldClass::ConfigDeclarationField,
        });
    }
}
