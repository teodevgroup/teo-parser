use maplit::btreemap;
use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::expression::{ExpressionKind, TypeAndValue};
use crate::ast::identifier::Identifier;
use crate::ast::literals::ArrayLiteral;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::namespace::Namespace;
use crate::ast::reference::ReferenceType;
use crate::ast::unit::Unit;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::r#type::Type;
use crate::resolver::resolve_argument_list::resolve_argument_list;
use crate::resolver::resolve_identifier::{resolve_identifier, resolve_identifier_with_filter};
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_middleware;

pub(super) fn resolve_use_middlewares_block<'a>(block: &'a UseMiddlewaresBlock, context: &'a ResolverContext<'a>) {
    resolve_use_middlewares_array_literal(&block.array_literal, context)
}

fn resolve_use_middlewares_array_literal<'a>(array_literal: &'a ArrayLiteral, context: &'a ResolverContext<'a>) {
    for expression in &array_literal.expressions {
        match &expression.kind {
            ExpressionKind::Identifier(i) => expression.resolve(resolve_middleware_identifier(i, context)),
            ExpressionKind::Unit(u) => expression.resolve(resolve_middleware_unit(u, context)),
            _ => context.insert_diagnostics_error(expression.span(), "unexpected middleware expression"),
        }
    }
}

fn resolve_middleware_identifier<'a>(identifier: &'a Identifier, context: &'a ResolverContext<'a>) -> TypeAndValue {
    if let Some(reference) = resolve_identifier(identifier, context, ReferenceType::Middleware, Availability::default()) {
        let declaration = context.schema.find_top_by_path(&reference).unwrap().as_middleware_declaration().unwrap();
        TypeAndValue {
            r#type: Type::Undetermined,
            value: Some(declaration.string_path.clone().into()),
        }
    } else {
        context.insert_diagnostics_error(identifier.span, "middleware not found");
        TypeAndValue {
            r#type: Type::Undetermined,
            value: Some(Value::Null),
        }
    }
}

fn resolve_middleware_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>) -> TypeAndValue {
    let mut current_space: Option<&Namespace> = None;
    let mut current_middleware: Option<&MiddlewareDeclaration> = None;
    let mut middleware_found = false;
    let mut argument_list_found = false;
    for (index, expression) in unit.expressions.iter().enumerate() {
        if argument_list_found {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            break;
        }
        match &expression.kind {
            ExpressionKind::Identifier(identifier) => {
                if middleware_found {
                    context.insert_diagnostics_error(expression.span(), "invalid expression");
                    break;
                }
                let new_reference = if current_space.is_some() {
                    current_space.unwrap().find_top_by_name(identifier.name(), &top_filter_for_middleware(), Availability::default())
                } else {
                    let r = resolve_identifier_with_filter(identifier, context, &top_filter_for_middleware(), Availability::default());
                    r.map(|r| context.schema.find_top_by_path(&r)).flatten()
                };
                if let Some(new_reference) = new_reference {
                    if new_reference.is_namespace() {
                        current_space = new_reference.as_namespace();
                    } else {
                        current_middleware = new_reference.as_middleware_declaration();
                        middleware_found = true;
                    }
                } else {
                    context.insert_diagnostics_error(expression.span(), "identifier not found");
                    break;
                }
            }
            ExpressionKind::ArgumentList(argument_list) => {
                if let Some(middleware_declaration) = current_middleware {
                    resolve_argument_list(
                        unit.expressions.get(index - 1).unwrap().span(),
                        Some(argument_list),
                        middleware_declaration.callable_variants(),
                        &btreemap! {},
                        context,
                        None
                    );
                } else {
                    break;
                }
                argument_list_found = true;
            }
            ExpressionKind::Call(call) => {
                let identifier = &call.identifier;
                if middleware_found {
                    context.insert_diagnostics_error(expression.span(), "invalid expression");
                    break;
                }
                let new_reference = if current_space.is_some() {
                    current_space.unwrap().find_top_by_name(identifier.name(), &top_filter_for_middleware(), Availability::default())
                } else {
                    let r = resolve_identifier_with_filter(identifier, context, &top_filter_for_middleware(), Availability::default());
                    r.map(|r| context.schema.find_top_by_path(&r)).flatten()
                };
                if let Some(new_reference) = new_reference {
                    if new_reference.is_namespace() {
                        current_space = new_reference.as_namespace();
                    } else {
                        current_middleware = new_reference.as_middleware_declaration();
                        middleware_found = true;
                    }
                } else {
                    context.insert_diagnostics_error(expression.span(), "identifier not found");
                    break;
                }
                if let Some(middleware_declaration) = current_middleware {
                    resolve_argument_list(
                        unit.expressions.get(index - 1).unwrap().span(),
                        Some(&call.argument_list),
                        middleware_declaration.callable_variants(),
                        &btreemap! {},
                        context,
                        None
                    );
                } else {
                    break;
                }
                argument_list_found = true;
            }
            _ => {
                context.insert_diagnostics_error(expression.span(), "invalid expression");
            }
        }
    }
    TypeAndValue {
        r#type: Type::Undetermined,
        value: if current_middleware.is_some() { Some(current_middleware.unwrap().string_path.clone().into()) } else { Some(Value::Null) },
    }
}