use std::sync::Arc;
use crate::ast::node::Node;
use crate::availability::Availability;
use crate::expr::ExprInfo;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::resolver::resolve_identifier::{resolve_identifier_path_names_with_filter_to_top, resolve_identifier_path_names_with_filter_to_top_multiple, top_to_expr_info};
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
    ).map(|t| top_to_expr_info(t, None))
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
    )
}

pub fn search_identifier_path_names_with_filter_to_expr_info_multiple(
    identifier_path_names: &Vec<&str>,
    schema: &Schema,
    source: &Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Vec<ExprInfo> {
    search_identifier_path_names_with_filter_to_top_multiple(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability
    ).iter().map(|t| top_to_expr_info(t, None)).collect()
}

pub fn search_identifier_path_names_with_filter_to_path_multiple(
    identifier_path_names: &Vec<&str>,
    schema: &Schema,
    source: &Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Vec<Vec<usize>> {
    search_identifier_path_names_with_filter_to_top_multiple(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability
    ).iter().map(|t| t.path().clone()).collect()
}

pub fn search_identifier_path_names_with_filter_to_top_multiple<'a>(
    identifier_path_names: &Vec<&str>,
    schema: &'a Schema,
    source: &'a Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Vec<&'a Node> {
    resolve_identifier_path_names_with_filter_to_top_multiple(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability,
    )
}
