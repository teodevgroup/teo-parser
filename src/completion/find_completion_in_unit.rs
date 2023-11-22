use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::expr::ExprInfo;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn find_completion_in_unit(schema: &Schema, source: &Source, unit: &Unit, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    if unit.expressions().count() == 0 {
        return vec![];
    }
    let mut previous_resolved = &ExprInfo::undetermined();
    for (index, expression) in unit.expressions().enumerate() {
        if expression.span().contains_line_col(line_col) {
            if index == 0 {
                return find_completion_in_expression(
                    schema,
                    source,
                    expression,
                    line_col,
                    namespace_path,
                    availability,
                );
            } else {

            }
        } else {
            previous_resolved = expression.resolved();
        }
    }
    vec![]
}
