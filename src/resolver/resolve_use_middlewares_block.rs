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
use crate::resolver::resolve_identifier::{resolve_identifier, resolve_identifier_with_diagnostic_message, resolve_identifier_with_filter};
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_middleware;

pub(super) fn resolve_use_middlewares_block<'a>(block: &'a UseMiddlewaresBlock, context: &'a ResolverContext<'a>) {
    resolve_use_middlewares_array_literal(&block.array_literal, context)
}

fn resolve_use_middlewares_array_literal<'a>(array_literal: &'a ArrayLiteral, context: &'a ResolverContext<'a>) {
    for expression in &array_literal.expressions {
        match &expression.kind {
            ExpressionKind::Identifier(i) => { expression.resolve(resolve_identifier_with_diagnostic_message(i, context)); },
            ExpressionKind::Unit(u) => { expression.resolve(resolve_unit(u, context, &Type::Middleware, &btreemap! {})); },
            _ => context.insert_diagnostics_error(expression.span(), "unexpected middleware expression"),
        }
    }
}
