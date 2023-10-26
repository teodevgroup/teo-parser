use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::expression::{Expression, ExpressionKind, ExpressionResolved};
use crate::ast::identifier::Identifier;
use crate::ast::literals::ArrayLiteral;
use crate::ast::reference::ReferenceType;
use crate::ast::unit::Unit;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::r#type::Type;
use crate::resolver::resolve_identifier::resolve_identifier;
use crate::resolver::resolver_context::ResolverContext;

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

fn resolve_middleware_identifier<'a>(identifier: &'a Identifier, context: &'a ResolverContext<'a>) -> ExpressionResolved {
    if let Some(reference) = resolve_identifier(identifier, context, ReferenceType::Middleware, Availability::default()) {
        let declaration = context.schema.find_top_by_path(&reference).unwrap().as_middleware_declaration().unwrap();
        ExpressionResolved {
            r#type: Type::Undetermined,
            value: Some(declaration.string_path.clone().into()),
        }
    } else {
        context.insert_diagnostics_error(identifier.span, "middleware not found");
        ExpressionResolved {
            r#type: Type::Undetermined,
            value: Some(Value::Null),
        }
    }
}

fn resolve_middleware_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>) -> ExpressionResolved {
    unreachable!()
}