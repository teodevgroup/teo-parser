use maplit::btreemap;
use crate::ast::handler::HandlerInputFormat;
use crate::ast::handler_template_declaration::HandlerTemplateDeclaration;
use crate::ast::reference_space::ReferenceSpace;
use crate::availability::Availability;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_handler_template_declaration_types<'a>(
    handler_template_declaration: &'a HandlerTemplateDeclaration,
    context: &'a ResolverContext<'a>
) {
    if context.has_examined_default_path(&handler_template_declaration.string_path, Availability::default()) {
        context.insert_duplicated_identifier(handler_template_declaration.identifier().span);
    }
    context.add_examined_default_path(handler_template_declaration.string_path.clone(), Availability::default());
    if let Some(input_type) = handler_template_declaration.input_type() {
        resolve_type_expr(input_type, &vec![], &vec![], &btreemap! {}, context, context.current_availability());
    }
    resolve_type_expr(handler_template_declaration.output_type(), &vec![], &vec![], &btreemap! {}, context, context.current_availability());
    if let Some(input_type) = handler_template_declaration.input_type() {
        match handler_template_declaration.input_format {
            HandlerInputFormat::Form => crate::resolver::resolve_handler_group::validate_handler_related_types(input_type.resolved(), input_type.span(), context, crate::resolver::resolve_handler_group::is_valid_form_input_type),
            HandlerInputFormat::Json => crate::resolver::resolve_handler_group::validate_handler_related_types(input_type.resolved(), input_type.span(), context, crate::resolver::resolve_handler_group::is_valid_json_input_type),
        }
    }
    crate::resolver::resolve_handler_group::validate_handler_related_types(&handler_template_declaration.output_type().resolved(), handler_template_declaration.output_type().span(), context, crate::resolver::resolve_handler_group::is_valid_json_output_type);
}

pub(super) fn resolve_handler_template_declaration_decorators<'a>(
    handler_template_declaration: &'a HandlerTemplateDeclaration,
    context: &'a ResolverContext<'a>
) {
    let keywords_map = btreemap!{};
    for decorator in handler_template_declaration.decorators() {
        resolve_decorator(decorator, context, &keywords_map, ReferenceSpace::HandlerDecorator);
    }
    let is_get_or_delete = if let Some(decorator) = handler_template_declaration.decorators().find(|d| d.identifier_path().identifiers().last().unwrap().name() == "map") {
        if let Some(argument_list) = decorator.argument_list() {
            if let Some(first_argument) = argument_list.arguments().next() {
                if first_argument.resolved().name.as_str() == "method" {
                    if let Some(value) = first_argument.value().resolved().value() {
                        if let Some(enum_variant) = value.as_enum_variant() {
                            enum_variant.value.as_str() == "get" || enum_variant.value.as_str() == "delete"
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };
    if is_get_or_delete && handler_template_declaration.input_type().is_some() {
        context.insert_diagnostics_error(handler_template_declaration.input_type().unwrap().span(), "get or delete handler template requires no input type");
    }
    if !is_get_or_delete && handler_template_declaration.input_type().is_none() {
        context.insert_diagnostics_error(handler_template_declaration.identifier().span(), "handler template requires input type");
    }
}