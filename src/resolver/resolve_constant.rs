use maplit::btreemap;
use crate::ast::constant_declaration::{ConstantDeclaration};
use crate::expr::ExprInfo;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_constant_references<'a>(constant: &'a ConstantDeclaration, context: &'a ResolverContext<'a>) {
    if constant.is_resolved() { return; }
    *constant.actual_availability.borrow_mut() = context.current_availability();
    if let Some(type_expr) = constant.type_expr() {
        resolve_type_expr(type_expr, &vec![], &vec![], &btreemap!{}, context, context.current_availability());
    }
    let undetermined = Type::Undetermined;
    context.push_dependency(constant.path.clone());
    let resolved = resolve_expression(constant.expression(), context, constant.type_expr().map_or(&undetermined, |t| t.resolved()), &btreemap! {});
    if let Some(type_expr) = constant.type_expr() {
        if type_expr.resolved().test(resolved.r#type()) {
            constant.resolve(ExprInfo {
                r#type: type_expr.resolved().clone(),
                value: resolved.value().cloned(),
                reference_info: resolved.reference_info().cloned(),
            });
        } else {
            if resolved.r#type().can_coerce_to(type_expr.resolved(), context.schema) {
                constant.resolve(ExprInfo {
                    r#type: type_expr.resolved().clone(),
                    value: if let Some(value) = resolved.value() {
                        resolved.r#type().coerce_value_to(value, type_expr.resolved())
                    } else {
                        None
                    },
                    reference_info: resolved.reference_info().cloned(),
                });
            } else {
                context.insert_diagnostics_error(constant.expression().span(), format!("expect {}, found {}", type_expr.resolved(), resolved.r#type()));
                constant.resolve(resolved.type_altered(type_expr.resolved().clone()));
            }
        }
    } else {
        constant.resolve(resolved);
    }
    context.pop_dependency();
}
