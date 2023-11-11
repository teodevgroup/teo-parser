use crate::ast::arith_expr::ArithExpr;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;

pub(super) fn find_completion_in_arith_expr(schema: &Schema, source: &Source, arith_expr: &ArithExpr, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    match arith_expr {
        ArithExpr::Expression(e) => find_completion_in_expression(schema, source, e.as_ref(), line_col, namespace_path, availability),
        ArithExpr::UnaryOperation(u) => if u.rhs.span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, u.rhs.as_ref(), line_col, namespace_path, availability)
        } else {
            vec![]
        }
        ArithExpr::BinaryOperation(b) => if b.lhs.span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, b.lhs.as_ref(), line_col, namespace_path, availability)
        } else if b.rhs.span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, b.rhs.as_ref(), line_col, namespace_path, availability)
        } else {
            vec![]
        }
        ArithExpr::UnaryPostfixOperation(p) => if p.lhs.span().contains_line_col(line_col) {
            find_completion_in_arith_expr(schema, source, p.lhs.as_ref(), line_col, namespace_path, availability)
        } else {
            vec![]
        }
    }
}
