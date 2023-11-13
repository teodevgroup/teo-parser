use crate::ast::namespace::Namespace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;

pub(crate) fn search_top<'a>(schema: &'a Schema, file_path: &str, line_col: (usize, usize)) -> Option<&'a Top> {
    if let Some(source) = schema.sources().iter().find(|s| s.file_path.as_str() == file_path) {
        return search_top_in_source(source, line_col);
    }
    None
}

fn search_top_in_source(source: &Source, line_col: (usize, usize)) -> Option<&Node> {
    for top in source.children() {
        if top.span().contains_line_col(line_col) {
            return if let Some(namespace) = top.as_namespace() {
                if let Some(top_in_namespace) = search_top_in_namespace(namespace, line_col) {
                    Some(top_in_namespace)
                } else {
                    Some(top)
                }
            } else {
                Some(top)
            }
        }
    }
    None
}

fn search_top_in_namespace(namespace: &Namespace, line_col: (usize, usize)) -> Option<&Node> {
    for top in namespace.tops() {
        if top.span().contains_line_col(line_col) {
            return if let Some(namespace) = top.as_namespace() {
                if let Some(top_in_namespace) = search_top_in_namespace(namespace, line_col) {
                    Some(top_in_namespace)
                } else {
                    Some(top)
                }
            } else {
                Some(top)
            }
        }
    }
    None
}