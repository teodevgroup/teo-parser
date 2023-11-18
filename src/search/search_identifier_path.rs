use std::sync::Arc;
use crate::ast::node::Node;
use crate::availability::Availability;
use crate::expr::ExprInfo;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::resolver::resolve_identifier::{resolve_identifier_path_names_with_filter_to_top, top_to_expr_info};
use crate::traits::identifiable::Identifiable;
use crate::traits::resolved::Resolve;

pub fn search_identifier_path_names_with_filter_to_expr_info(
    identifier_path_names: &Vec<&str>,
    schema: &Schema,
    source: &Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<ExprInfo> {
    search_identifier_path_names_with_filter_to_top(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability
    ).map(|t| top_to_expr_info(t))
}

pub fn search_identifier_path_names_with_filter_to_path(
    identifier_path_names: &Vec<&str>,
    schema: &Schema,
    source: &Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<Vec<usize>> {
    search_identifier_path_names_with_filter_to_top(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability
    ).map(|t| t.path().clone())
}

pub fn search_identifier_path_names_with_filter_to_top<'a>(
    identifier_path_names: &Vec<&str>,
    schema: &'a Schema,
    source: &'a Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<&'a Node> {
    resolve_identifier_path_names_with_filter_to_top(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability,
        None,
    )
}
