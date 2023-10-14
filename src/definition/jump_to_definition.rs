use crate::ast::schema::Schema;
use crate::ast::top::Top;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_config::jump_to_definition_in_config;
use crate::definition::jump_to_definition_in_constant::jump_to_definition_in_constant;
use crate::definition::jump_to_definition_in_import::jump_to_definition_in_import;
use crate::definition::jump_to_definition_in_model::jump_to_definition_in_model;
use crate::search::search_top::search_top;

pub fn jump_to_definition(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<Definition> {
    if let Some(source) = schema.source_at_path(file_path) {
        if let Some(top) = search_top(schema, file_path, line_col) {
            return match top {
                Top::Import(i) => jump_to_definition_in_import(schema, source, i, line_col),
                Top::Model(m) => jump_to_definition_in_model(schema, source, m, line_col),
                Top::Constant(c) => jump_to_definition_in_constant(schema, source, c, line_col),
                Top::Config(c) => jump_to_definition_in_config(schema, source, c, line_col),
                _ => vec![]
            };
        }
    }
    vec![]
}