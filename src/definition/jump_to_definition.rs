use crate::ast::schema::Schema;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_config::jump_to_definition_in_config;
use crate::definition::jump_to_definition_in_config_declaration::jump_to_definition_in_config_declaration;
use crate::definition::jump_to_definition_in_constant::jump_to_definition_in_constant;
use crate::definition::jump_to_definition_in_decorator_declaration::jump_to_definition_in_decorator_declaration;
use crate::definition::jump_to_definition_in_enum_declaration::jump_to_definition_in_enum_declaration;
use crate::definition::jump_to_definition_in_handler_declaration::jump_to_definition_in_handler_group_declaration;
use crate::definition::jump_to_definition_in_import::jump_to_definition_in_import;
use crate::definition::jump_to_definition_in_interface::jump_to_definition_in_interface;
use crate::definition::jump_to_definition_in_middleware_declaration::jump_to_definition_in_middleware_declaration;
use crate::definition::jump_to_definition_in_model::jump_to_definition_in_model;
use crate::definition::jump_to_definition_in_pipeline_item_declaration::jump_to_definition_in_pipeline_item_declaration;
use crate::definition::jump_to_definition_in_struct_declaration::jump_to_definition_in_struct_declaration;
use crate::search::search_top::search_top;

pub fn jump_to_definition(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<Definition> {
    if let Some(source) = schema.source_at_path(file_path) {
        if let Some(top) = search_top(schema, file_path, line_col) {
            return match top {
                Top::Import(i) => jump_to_definition_in_import(schema, source, i, line_col),
                Top::Model(m) => jump_to_definition_in_model(schema, source, m, line_col),
                Top::Interface(i) => jump_to_definition_in_interface(schema, source, i, line_col),
                Top::Constant(c) => jump_to_definition_in_constant(schema, source, c, line_col),
                Top::Config(c) => jump_to_definition_in_config(schema, source, c, line_col),
                Top::ConfigDeclaration(c) => jump_to_definition_in_config_declaration(schema, source, c, line_col),
                Top::PipelineItemDeclaration(p) => jump_to_definition_in_pipeline_item_declaration(schema, source, p, line_col),
                Top::DecoratorDeclaration(d) => jump_to_definition_in_decorator_declaration(schema, source, d, line_col),
                Top::StructDeclaration(s) => jump_to_definition_in_struct_declaration(schema, source, s, line_col),
                Top::HandlerGroup(h) => jump_to_definition_in_handler_group_declaration(schema, source, h, line_col),
                Top::Enum(e) => jump_to_definition_in_enum_declaration(schema, source, e, line_col),
                Top::Middleware(m) => jump_to_definition_in_middleware_declaration(schema, source, m, line_col),
                Top::DataSet(_) => vec![],
                Top::Namespace(_) => vec![],
                Top::UseMiddlewareBlock(_) => vec![],
            };
        }
    }
    vec![]
}