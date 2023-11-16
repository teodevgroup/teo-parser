use crate::ast::node::Node;
use crate::ast::schema::Schema;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_config::find_completion_in_config;
use crate::completion::find_completion_in_config_declaration::find_completion_in_config_declaration;
use crate::completion::find_completion_in_constant_declaration::find_completion_in_constant_declaration;
use crate::completion::find_completion_in_data_set_declaration::find_completion_in_data_set_declaration;
use crate::completion::find_completion_in_decorator_declaration::find_completion_in_decorator_declaration;
use crate::completion::find_completion_in_enum_declaration::find_completion_in_enum_declaration;
use crate::completion::find_completion_in_handler_group::find_completion_in_handler_group_declaration;
use crate::completion::find_completion_in_interface::find_completion_in_interface;
use crate::completion::find_completion_in_middleware_declaration::find_completion_in_middleware_declaration;
use crate::completion::find_completion_in_model::find_completion_in_model;
use crate::completion::find_completion_in_pipeline_item_declaration::find_completion_in_pipeline_item_declaration;
use crate::completion::find_completion_in_struct_declaration::find_completion_in_struct_declaration;
use crate::completion::find_completion_in_use_middleware_block::find_completion_in_use_middleware_block;
use crate::search::search_top::search_top;

pub fn find_completion(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if let Some(source) = schema.source_at_path(file_path) {
        if let Some(top) = search_top(schema, file_path, line_col) {
            match top {
                Node::Model(m) => {
                    return find_completion_in_model(schema, source, m, line_col);
                }
                Node::InterfaceDeclaration(i) => {
                    return find_completion_in_interface(schema, source, i, line_col);
                }
                Node::StructDeclaration(s) => {
                    return find_completion_in_struct_declaration(schema, source, s, line_col);
                }
                Node::ConfigDeclaration(c) => {
                    return find_completion_in_config_declaration(schema, source, c, line_col);
                }
                Node::Config(c) => {
                    return find_completion_in_config(schema, source, c, line_col);
                }
                Node::Enum(e) => {
                    return find_completion_in_enum_declaration(schema, source, e, line_col);
                }
                Node::Constant(c) => {
                    return find_completion_in_constant_declaration(schema, source, c, line_col);
                }
                Node::DataSet(d) => {
                    return find_completion_in_data_set_declaration(schema, source, d, line_col);
                }
                Node::MiddlewareDeclaration(m) => {
                    return find_completion_in_middleware_declaration(schema, source, m, line_col);
                }
                Node::HandlerGroupDeclaration(h) => {
                    return find_completion_in_handler_group_declaration(schema, source, h, line_col);
                }
                Node::DecoratorDeclaration(d) => {
                    return find_completion_in_decorator_declaration(schema, source, d, line_col);
                }
                Node::PipelineItemDeclaration(p) => {
                    return find_completion_in_pipeline_item_declaration(schema, source, p, line_col);
                }
                Node::UseMiddlewaresBlock(u) => {
                    return find_completion_in_use_middleware_block(schema, source, u, line_col);
                }
                _ => ()
            }
        }
    }
    vec![]
}