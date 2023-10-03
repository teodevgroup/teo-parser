use crate::ast::action::{ActionDeclaration, ActionDeclarationResolved, ActionGroupDeclaration, ActionInputFormat};
use crate::ast::r#type::{Type, TypeExpr, TypeShape};
use crate::resolver::resolve_type_expr::{resolve_type_expr, resolve_type_shape};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_action_group<'a>(
    action_group: &'a ActionGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    for action_declaration in &action_group.action_declarations {
        resolve_action_declaration(action_declaration, context)
    }
}

pub(super) fn resolve_action_declaration<'a>(
    action_declaration: &'a ActionDeclaration,
    context: &'a ResolverContext<'a>,
) {
    if context.has_examined_action_path(&action_declaration.string_path) {
        context.insert_diagnostics_error(action_declaration.identifier.span, "DefinitionError: duplicated definition of action");
    } else {
        context.add_examined_action_path(action_declaration.string_path.clone());
    }
    resolve_type_expr(&action_declaration.input_type, None, None, context);
    resolve_type_expr(&action_declaration.output_type, None, None, context);
    action_declaration.resolve(ActionDeclarationResolved {
        input_shape: resolve_type_shape(action_declaration.input_type.resolved(), context),
        output_shape: resolve_type_shape(action_declaration.output_type.resolved(), context),
    });
    match action_declaration.input_format {
        ActionInputFormat::Form => validate_form_input_type(&action_declaration.resolved().input_shape, context),
        ActionInputFormat::Json => validate_json_input_type(&action_declaration.resolved().input_shape, context),
    }
    validate_json_output_type(&action_declaration.resolved().output_shape, context);
}

fn validate_form_input_type<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) {
    let r#type = type_expr.resolved();
    if r#type.is_any() {
        return
    } else if r#type.is_interface() {
        let interface = context.schema.find_top_by_path(r#type.interface_path().unwrap()).unwrap().as_interface().unwrap();
        for extend in interface.extends() {

        }
    } else {
        context.insert_diagnostics_error(type_expr.span(), "TypeError: form action input type should be interface or any")
    }
}

fn validate_json_input_type<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) {
    let r#type = type_expr.resolved();
    if r#type.is_any() {
        return
    } else if r#type.is_interface() {

    } else {
        context.insert_diagnostics_error(type_expr.span(), "TypeError: action input type should be interface or any")
    }
}

fn validate_json_output_type<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) {
    let r#type = type_expr.resolved();
    if r#type.contains(|t| t.is_file()) {

    }
}