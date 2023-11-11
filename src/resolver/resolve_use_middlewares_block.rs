use maplit::btreemap;
use crate::ast::expression::ExpressionKind;
use crate::ast::literals::ArrayLiteral;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::r#type::Type;
use crate::resolver::resolve_identifier::resolve_identifier_with_diagnostic_message;
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;

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
