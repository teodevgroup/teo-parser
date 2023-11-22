use crate::ast::identifier::Identifier;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::availability::Availability;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn find_completion_in_identifier(schema: &Schema, source: &Source, identifier: &Identifier, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    if identifier.span.contains_line_col(line_col) {
        find_top_completion_with_filter(
            schema,
            source,
            namespace_path,
            &vec![],
            &top_filter_for_reference_type(ReferenceSpace::Default),
            availability,
        )
    } else {
        vec![]
    }
}
