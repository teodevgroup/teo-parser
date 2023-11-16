use crate::ast::constant::Constant;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::completion::find_completion_in_type_expr::{find_completion_in_type_expr, TypeExprFilter};
use crate::traits::info_provider::InfoProvider;
use crate::traits::node_trait::NodeTrait;

pub(super) fn find_completion_in_constant_declaration(schema: &Schema, source: &Source, constant: &Constant, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if constant.expression().span().contains_line_col(line_col) {
        return find_completion_in_expression(schema, source, constant.expression(), line_col, &constant.namespace_str_path(), constant.define_availability);
    }
    if let Some(type_expr) = constant.type_expr() {
        if type_expr.span().contains_line_col(line_col) {
            return find_completion_in_type_expr(schema, source, type_expr, line_col, &constant.namespace_str_path(), &vec![], TypeExprFilter::None, constant.define_availability);
        }
    }
    vec![]
}