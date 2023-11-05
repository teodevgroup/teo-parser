use crate::ast::arith::ArithExpr;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_arith_expr(schema: &Schema, source: &Source, arith_expr: &ArithExpr, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
