use indexmap::indexmap;
use crate::ast::synthesized_shape_declaration::SynthesizedShapeDeclaration;
use crate::ast::synthesized_shape_field_declaration::SynthesizedShapeFieldDeclaration;
use crate::resolver::resolve_field::{FieldParentType, resolve_field_class, resolve_field_types};
use crate::resolver::resolve_identifier::{resolve_identifier_path, resolve_identifier_path_with_filter};
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_any_model_field_decorators;

pub(super) fn resolve_declared_synthesized_shape<'a>(synthesized_shape_declaration: &'a SynthesizedShapeDeclaration, context: &'a ResolverContext<'a>) {
    if context.has_examined_default_path(&synthesized_shape_declaration.string_path, synthesized_shape_declaration.define_availability) {
        context.insert_duplicated_identifier(synthesized_shape_declaration.identifier().span);
    }
    *synthesized_shape_declaration.actual_availability.borrow_mut() = context.current_availability();
    for partial_field in synthesized_shape_declaration.partial_fields() {
        context.insert_diagnostics_error(partial_field.span, "partial field");
    }
    for field in synthesized_shape_declaration.static_fields() {
        resolve_field_class(
            field,
            FieldParentType::Interface,
            context,
        );
        resolve_field_types(
            field,
            None,
            None,
            context
        );
    }
    context.add_examined_default_path(synthesized_shape_declaration.string_path.clone(), synthesized_shape_declaration.define_availability);
    let mut map = indexmap! {};
    let mut existing_keys = vec![];
    for field in synthesized_shape_declaration.static_fields() {
        if !existing_keys.contains(&field.identifier().name()) {
            map.insert(field.identifier().name().to_owned(), field.type_expr().resolved().clone());
            existing_keys.push(field.identifier().name());
        }
    }
    synthesized_shape_declaration.resolved_mut().base_shape = map;
    for dynamic_field in synthesized_shape_declaration.dynamic_fields() {
        resolve_synthesized_shape_field_declaration(dynamic_field, context);
    }
}

pub(super) fn resolve_synthesized_shape_field_declaration<'a>(synthesized_shape_field_declaration: &'a SynthesizedShapeFieldDeclaration, context: &'a ResolverContext<'a>) {
    *synthesized_shape_field_declaration.actual_availability.borrow_mut() = context.current_availability();
    if let Some(expr_info) = resolve_identifier_path_with_filter(synthesized_shape_field_declaration.decorator_identifier_path(), context, &top_filter_for_any_model_field_decorators(), context.current_availability()) {
        synthesized_shape_field_declaration.resolved_mut().decorator_full_path = Some(expr_info.reference_info().unwrap().reference().string_path().clone());
    } else {
        context.insert_diagnostics_error(synthesized_shape_field_declaration.decorator_identifier_path().span(), "decorator not found");
    }
}