use maplit::btreemap;
use pest::Parser;
use crate::ast::node::Node;
use crate::ast::source::{Source, SourceReferences};
use crate::parse_append;
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_handler_group::parse_handler_group_declaration;
use crate::parser::parse_config_block::parse_config_block;
use crate::parser::parse_config_declaration::parse_config_declaration;
use crate::parser::parse_constant_statement::parse_constant_statement;
use crate::parser::parse_data_set_declaration::parse_data_set_declaration;
use crate::parser::parse_decorator_declaration::parse_decorator_declaration;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_enum::parse_enum_declaration;
use crate::parser::parse_import_statement::parse_import_statement;
use crate::parser::parse_interface_declaration::parse_interface_declaration;
use crate::parser::parse_middleware_declaration::parse_middleware_declaration;
use crate::parser::parse_model::parse_model_declaration;
use crate::parser::parse_namespace::parse_namespace;
use crate::parser::parse_pipeline_item_declaration::parse_pipeline_item_declaration;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_struct_declaration::parse_struct_declaration;
use crate::parser::parse_use_middlewares_block::parse_use_middlewares_block;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::SchemaParser;
use crate::traits::identifiable::Identifiable;
use super::pest_parser::Rule;

pub(super) fn parse_source(
    content: &str, path: impl Into<String>, builtin: bool, context: &mut ParserContext,
) -> Source {
    let path = path.into();
    let id = context.start_next_source(path.clone());
    if builtin || path.as_str().ends_with("builtin/std.teo") {
        context.set_is_builtin_source();
    }
    let mut children = btreemap!{};
    let mut references = SourceReferences::new();
    let mut pairs = match SchemaParser::parse(Rule::schema, &content) {
        Ok(pairs) => pairs,
        Err(err) => panic!("{}", err)
    };
    let pairs = pairs.next().unwrap();
    let mut pairs = pairs.into_inner().peekable();
    while let Some(current) = pairs.next() {
        match current.as_rule() {
            Rule::triple_comment_block => {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            }
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::import_statement => { // import { a, b } from './some.schema'
                let import = parse_import_statement(current, path.as_ref(), context);
                let import_span = import.source.span;
                let import_file_path = import.file_path.clone();
                references.imports.insert(import.id());
                children.insert(import.id(), Node::Import(import));
                if context.is_import_file_path_examined(&import_file_path) {
                    context.insert_error(import_span, "Duplicated import")
                } else {
                    context.add_examined_import_file(import_file_path);
                }
            },
            Rule::constant_statement => { // let a = 5
                let constant = parse_constant_statement(current, context);
                references.constants.insert(constant.id());
                children.insert(constant.id(), Node::Constant(constant));
            },
            Rule::config_block => { // server { ... }
                let config = parse_config_block(current, context);
                references.configs.insert(config.id());
                context.schema_references.add_config(&config);
                if config.keyword.is_connector() {
                    references.connector = Some(config.id());
                }
                children.insert(config.id(), Node::Config(config));
            },
            Rule::use_middlewares_block => { // middlewares [ ... ]
                let middlewares = parse_use_middlewares_block(current, context);
                references.use_middlewares_block = Some(middlewares.id());
                context.schema_references.use_middlewares_blocks.push(middlewares.path.clone());
                children.insert(middlewares.id(), Node::UseMiddlewareBlock(middlewares));
            },
            Rule::model_declaration => { // model A { ... }
                let model = parse_model_declaration(current, context);
                references.models.insert(model.id());
                context.schema_references.models.push(model.path.clone());
                children.insert(model.id(), Node::Model(model));
            },
            Rule::enum_declaration => { // enum A { ... }
                let r#enum = parse_enum_declaration(current, context);
                references.enums.insert(r#enum.id());
                context.schema_references.enums.push(r#enum.path.clone());
                children.insert(r#enum.id(), Node::Enum(r#enum));
            },
            Rule::dataset_declaration => { // dataset a { ... }
                let data_set = parse_data_set_declaration(current, context);
                references.data_sets.insert(data_set.id());
                context.schema_references.data_sets.push(data_set.path.clone());
                children.insert(data_set.id(), Node::DataSet(data_set));
            },
            Rule::interface_declaration => { // interface a { ... }
                let interface = parse_interface_declaration(current, context);
                references.interfaces.insert(interface.id());
                context.schema_references.interfaces.push(interface.path.clone());
                children.insert(interface.id(), Node::InterfaceDeclaration(interface));
            },
            Rule::namespace => {
                let namespace = parse_namespace(current, context);
                references.namespaces.insert(namespace.id());
                context.schema_references.namespaces.push(namespace.path.clone());
                children.insert(namespace.id(), Node::Namespace(namespace));
            }
            // declares
            Rule::config_declaration => {
                let config_declaration = parse_config_declaration(current, context);
                references.config_declarations.insert(config_declaration.id());
                context.schema_references.config_declarations.push(config_declaration.path.clone());
                children.insert(config_declaration.id(), Node::ConfigDeclaration(config_declaration));
            }
            Rule::decorator_declaration => {
                let decorator_declaration = parse_decorator_declaration(current, context);
                references.decorator_declarations.insert(decorator_declaration.id());
                context.schema_references.decorator_declarations.push(decorator_declaration.path.clone());
                children.insert(decorator_declaration.id(), Node::DecoratorDeclaration(decorator_declaration));
            }
            Rule::pipeline_item_declaration => {
                let pipeline_item_declaration = parse_pipeline_item_declaration(current, context);
                references.pipeline_item_declarations.insert(pipeline_item_declaration.id());
                context.schema_references.pipeline_item_declarations.push(pipeline_item_declaration.path.clone());
                children.insert(pipeline_item_declaration.id(), Node::PipelineItemDeclaration(pipeline_item_declaration));
            },
            Rule::middleware_declaration => {
                let middleware_declaration = parse_middleware_declaration(current, context);
                references.middlewares.insert(middleware_declaration.id());
                context.schema_references.middlewares.push(middleware_declaration.path.clone());
                children.insert(middleware_declaration.id(), Node::MiddlewareDeclaration(middleware_declaration));
            },
            Rule::handler_group_declaration => {
                let handler_group_declaration = parse_handler_group_declaration(current, context);
                references.handler_groups.insert(handler_group_declaration.id());
                context.schema_references.handler_groups.push(handler_group_declaration.path.clone());
                children.insert(handler_group_declaration.id(), Node::HandlerGroupDeclaration(handler_group_declaration));
            },
            Rule::struct_declaration => {
                let struct_declaration = parse_struct_declaration(current, context);
                references.handler_groups.insert(struct_declaration.id());
                context.schema_references.struct_declarations.push(struct_declaration.path.clone());
                children.insert(struct_declaration.id(), Node::StructDeclaration(struct_declaration));
            }
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), children),
            Rule::CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    if builtin {
        context.schema_references.builtin_sources.push(id);
    } else {
        context.schema_references.user_sources.push(id);
    }
    Source::new(
        id,
        builtin || path.as_str().ends_with("builtin/std.teo"),
        path,
        children,
        references
    )
}