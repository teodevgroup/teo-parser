use serde::Serialize;
use crate::ast::schema::Schema;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_model::jump_to_definition_in_model;
use crate::search::search_top::search_top;

pub fn jump_to_definition(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<Definition> {
    if let Some(source) = schema.source_at_path(file_path) {
        if let Some(top) = search_top(schema, file_path, line_col) {
            match top {
                Top::Model(m) => {
                    return jump_to_definition_in_model(schema, source, m, line_col);
                }
                _ => ()
            }
        }
    }
    vec![]
}