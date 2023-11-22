use crate::ast::arith_expr::ArithExpr;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::r#type::Type;
use crate::traits::node_trait::NodeTrait;

pub(super) fn find_completion_in_arith_expr(schema: &Schema, source: &Source, arith_expr: &ArithExpr, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type, availability: Availability) -> Vec<CompletionItem> {
    match arith_expr {
        ArithExpr::Expression(e) => find_completion_in_expression(schema, source, e.as_ref(), line_col, namespace_path, expect, availability),
        ArithExpr::UnaryOperation(u) => if u.rhs().span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, u.rhs(), line_col, namespace_path, expect, availability)
        } else {
            vec![]
        }
        ArithExpr::BinaryOperation(b) => if b.lhs().span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, b.lhs(), line_col, namespace_path, expect, availability)
        } else if b.rhs().span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, b.rhs(), line_col, namespace_path, expect, availability)
        } else {
            vec![]
        }
        ArithExpr::UnaryPostfixOperation(p) => if p.lhs().span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, p.lhs(), line_col, namespace_path, expect, availability)
        } else {
            vec![]
        }
    }
}
