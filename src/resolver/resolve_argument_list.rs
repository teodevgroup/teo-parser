use crate::ast::argument::ArgumentResolved;
use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::argument_list::ArgumentList;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::Type;
use crate::diagnostics::diagnostics::{DiagnosticsError, DiagnosticsLog, DiagnosticsWarning};
use crate::resolver::resolve_expression::resolve_expression_and_unwrap_value;
use crate::resolver::resolver_context::ResolverContext;

pub(super) struct CallableVariant<'a> {
    pub(super) generics_declaration: Option<&'a GenericsDeclaration>,
    pub(super) argument_list_declaration: Option<&'a ArgumentListDeclaration>,
    pub(super) generics_contraint: Option<&'a GenericsConstraint>,
}

pub(super) fn resolve_argument_list<'a>(
    callable_identifier: &Identifier,
    argument_list: Option<&'a ArgumentList>,
    callable_variants: Vec<CallableVariant<'a>>,
    context: &'a ResolverContext<'a>,
) {
    if let Some(argument_list) = argument_list {
        if callable_variants.len() == 1 {
            let (errors, warnings) = try_resolve_argument_list_for_callable_variant(
                argument_list,
                callable_variants.first().unwrap(),
                context
            );
            for error in errors {
                context.insert_diagnostics_error(*error.span(), error.message());
            }
            for warning in warnings {
                context.insert_diagnostics_error(*warning.span(), warning.message());
            }
        } else {
            for callable_variant in &callable_variants {
                let (errors, warnings) = try_resolve_argument_list_for_callable_variant(
                    argument_list,
                    callable_variant,
                    context
                );
                if errors.is_empty() {
                    for warning in warnings {
                        context.insert_diagnostics_error(*warning.span(), warning.message());
                    }
                    return
                }
            }
            context.insert_diagnostics_error(argument_list.span, "Argument list doesn't match any callable variants");
        }
    } else {
        for callable_variant in &callable_variants {
            if let Some(argument_list_declaration) = callable_variant.argument_list_declaration {
                if argument_list_declaration.every_argument_is_optional() {
                    return
                }
            } else {
                return
            }
        }
        context.insert_diagnostics_error(callable_identifier.span, "Callable requires arguments");
    }
}

fn try_resolve_argument_list_for_callable_variant<'a>(
    argument_list: &'a ArgumentList,
    callable_variant: &CallableVariant<'a>,
    context: &'a ResolverContext<'a>,
) -> (Vec<DiagnosticsError>, Vec<DiagnosticsWarning>) {
    let mut errors = vec![];
    let mut warnings = vec![];
    if let Some(argument_list_declaration) = callable_variant.argument_list_declaration {
        let mut declaration_names: Vec<&str> = argument_list_declaration.argument_declarations.iter().map(|d| d.name.name()).collect();
        // match named arguments
        for named_argument in argument_list.arguments().iter().filter(|a| a.name.is_some()) {
            if let Some(argument_declaration) = argument_list_declaration.get(named_argument.name.as_ref().unwrap().name()) {
                resolve_expression_and_unwrap_value(&named_argument.value, context, argument_declaration.type_expr.resolved());
                if !context.check_value_type(argument_declaration.type_expr.resolved(), named_argument.value.resolved().as_value().unwrap()) {
                    errors.push(context.generate_diagnostics_error(named_argument.value.span(), "Argument value is of wrong type"))
                }
                declaration_names = declaration_names.iter().filter(|d| (**d) != argument_declaration.name.name()).map(|s| *s).collect();
            } else {
                let undetermined = Type::Undetermined;
                resolve_expression_and_unwrap_value(&named_argument.value, context, &undetermined);
                errors.push(context.generate_diagnostics_error(named_argument.name.as_ref().unwrap().span, "Undefined argument"))
            }
        }
        // remove named optional declarations and fire errors for named required declarations
        for name in declaration_names.clone() {
            if let Some(argument_declaration) = argument_list_declaration.get(name) {
                if !argument_declaration.name_optional {
                    if !argument_declaration.type_expr.resolved().is_optional() {
                        errors.push(context.generate_diagnostics_error(argument_declaration.span, format!("Missing argument '{}'", name)));
                    }
                    declaration_names = declaration_names.iter().filter(|d| (**d) != argument_declaration.name.name()).map(|s| *s).collect();
                }
            }
        }
        // match unnamed arguments
        for unnamed_argument in argument_list.arguments().iter().filter(|a| a.name.is_none()) {
            if let Some(name) = declaration_names.last() {
                if let Some(argument_declaration) = argument_list_declaration.get(name) {
                    resolve_expression_and_unwrap_value(&unnamed_argument.value, context, argument_declaration.type_expr.resolved());
                    if !context.check_value_type(argument_declaration.type_expr.resolved(), unnamed_argument.value.resolved().as_value().unwrap()) {
                        errors.push(context.generate_diagnostics_error(unnamed_argument.value.span(), "Argument value is of wrong type"))
                    }
                    unnamed_argument.resolve(ArgumentResolved {
                        name: name.to_string()
                    });
                    declaration_names = declaration_names.iter().filter(|d| *d != name).map(|s| *s).collect();
                }
            } else {
                errors.push(context.generate_diagnostics_error(unnamed_argument.span, "Redundant argument"));
            }
        }
        // fire errors for required unnamed declarations
        for declaration_name in declaration_names {
            if let Some(argument_declaration) = argument_list_declaration.get(declaration_name) {
                if !argument_declaration.type_expr.resolved().is_optional() {
                    errors.push(context.generate_diagnostics_error(argument_declaration.span, format!("Missing argument '{}'", declaration_name)));
                }
            }
        }
    } else {
        if !argument_list.arguments().is_empty() {
            errors.push(context.generate_diagnostics_error(argument_list.span, "Callable requires no arguments"));
        }
    }
    (errors, warnings)
}