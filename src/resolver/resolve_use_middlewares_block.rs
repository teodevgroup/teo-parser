use maplit::btreemap;
use crate::ast::arith_expr::ArithExpr;
use crate::ast::expression::ExpressionKind;
use crate::ast::literals::ArrayLiteral;
use crate::ast::unit::Unit;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::expr::{ExprInfo, ReferenceInfo, ReferenceType};
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::resolver::resolve_argument_list::resolve_argument_list;
use crate::resolver::resolve_identifier::{resolve_identifier_path_names_with_filter_to_top, resolve_identifier_with_diagnostic_message};
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_middleware;

pub(super) fn resolve_use_middlewares_block<'a>(block: &'a UseMiddlewaresBlock, context: &'a ResolverContext<'a>) {
    resolve_use_middlewares_array_literal(block.array_literal(), context)
}

fn resolve_use_middlewares_array_literal<'a>(array_literal: &'a ArrayLiteral, context: &'a ResolverContext<'a>) {
    for expression in array_literal.expressions() {
        match &expression.kind {
            ExpressionKind::Identifier(i) => { expression.resolve(resolve_identifier_with_diagnostic_message(i, context)); },
            ExpressionKind::Unit(u) => { expression.resolve(resolve_unit(u, context, &Type::Middleware, &btreemap! {})); },
            ExpressionKind::ArithExpr(a) => match a {
                ArithExpr::Expression(e) => match &e.as_ref().kind {
                    ExpressionKind::Unit(u) => { expression.resolve(resolve_middleware_unit(u, context)); },
                    _ => context.insert_diagnostics_error(expression.span(), "unexpected middleware expression"),
                },
                _ => context.insert_diagnostics_error(expression.span(), "unexpected middleware expression"),
            }
            _ => context.insert_diagnostics_error(expression.span(), "unexpected middleware expression"),
        }
    }
}

fn resolve_middleware_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>) -> ExprInfo {
    let mut path = vec![];
    let mut arg_list = None;
    for expression in unit.expressions() {
        match &expression.kind {
            ExpressionKind::Identifier(identifier) => path.push(identifier.name()),
            ExpressionKind::ArgumentList(argument_list) => arg_list = Some(argument_list),
            _ => (),
        }
    }
    if let Some(middleware_declaration) = resolve_identifier_path_names_with_filter_to_top(
        &path,
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_middleware(),
        context.current_availability(),
    ).map(|t| t.as_middleware_declaration()).flatten() {
        if middleware_declaration.argument_list_declaration().is_none() {
            if !arg_list.is_none() {
                context.insert_diagnostics_error(arg_list.unwrap().span, "middleware requires no arguments")
            }
        } else if let Some(argument_list) = middleware_declaration.argument_list_declaration() {
            if !argument_list.every_argument_is_optional() && arg_list.is_none() {
                context.insert_diagnostics_error(unit.span, "middleware requires argument list");
            }
            if let Some(arg_list) = arg_list {
                resolve_argument_list(unit.span, Some(arg_list), middleware_declaration.callable_variants(), &btreemap! {}, context, None);
            }
        }
        ExprInfo {
            r#type: Type::Middleware,
            value: None,
            reference_info: Some(ReferenceInfo::new(ReferenceType::Middleware, Reference::new(middleware_declaration.path.clone(), middleware_declaration.string_path.clone()), None)),
        }
    } else {
        ExprInfo::undetermined()
    }
}