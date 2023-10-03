use crate::ast::action::{ActionDeclaration, ActionGroupDeclaration, ActionInputFormat};
use crate::ast::r#type::Type;
use crate::resolver::resolve_type_expr::resolve_type_expr;
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
    match action_declaration.input_format {
        ActionInputFormat::Form => validate_form_input_type(action_declaration.input_type.resolved(), context),
        ActionInputFormat::Json => validate_json_input_type(action_declaration.input_type.resolved(), context),
    }
    validate_json_output_type(action_declaration.output_type.resolved(), context);
}

fn validate_form_input_type<'a>(r#type: &'a Type, context: &'a ResolverContext<'a>) {

}

fn validate_json_input_type<'a>(r#type: &'a Type, context: &'a ResolverContext<'a>) {

}

fn validate_json_output_type<'a>(r#type: &'a Type, context: &'a ResolverContext<'a>) {

}