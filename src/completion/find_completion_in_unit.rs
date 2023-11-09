use crate::ast::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::search::search_unit_for_definition::search_unit_for_definition;

pub(super) fn find_completion_in_unit(schema: &Schema, source: &Source, unit: &Unit, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    if unit.expressions.len() == 1 {
        find_completion_in_expression(
            schema,
            source,
            unit.expressions.get(0).unwrap(),
            line_col,
            namespace_path,
            availability,
        )
    } else {
        vec![]
    }
}