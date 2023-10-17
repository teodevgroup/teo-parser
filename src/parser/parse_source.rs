use maplit::btreemap;
use pest::Parser;
use crate::ast::source::{Source, SourceReferences, SourceType};
use crate::ast::top::Top;
use crate::parser::parse_action_group::parse_action_group_declaration;
use crate::parser::parse_config_block::parse_config_block;
use crate::parser::parse_config_declaration::parse_config_declaration;
use crate::parser::parse_constant_statement::parse_constant_statement;
use crate::parser::parse_data_set_declaration::parse_data_set_declaration;
use crate::parser::parse_decorator_declaration::parse_decorator_declaration;
use crate::parser::parse_enum::parse_enum_declaration;
use crate::parser::parse_import_statement::parse_import_statement;
use crate::parser::parse_interface_declaration::parse_interface_declaration;
use crate::parser::parse_middleware::parse_middleware;
use crate::parser::parse_model::parse_model_declaration;
use crate::parser::parse_namespace::parse_namespace;
use crate::parser::parse_pipeline_item_declaration::parse_pipeline_item_declaration;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_struct_declaration::parse_struct_declaration;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::SchemaParser;
use super::pest_parser::Rule;

pub(super) fn parse_source(
    content: &str, path: impl Into<String>, builtin: bool, context: &mut ParserContext,
) -> Source {
    let path = path.into();
    let id = context.start_next_source(path.clone());
    if builtin {
        context.set_is_builtin_source();
    }
    let mut tops = btreemap!{};
    let mut references = SourceReferences::new();
    let mut pairs = match SchemaParser::parse(Rule::schema, &content) {
        Ok(pairs) => pairs,
        Err(err) => panic!("{}", err)
    };
    let pairs = pairs.next().unwrap();
    let mut pairs = pairs.into_inner().peekable();
    while let Some(current) = pairs.next() {
        match current.as_rule() {
            Rule::import_statement => { // import { a, b } from './some.schema'
                let import = parse_import_statement(current, path.as_ref(), context);
                let import_span = import.source.span;
                let import_file_path = import.file_path.clone();
                references.imports.insert(import.id());
                tops.insert(import.id(), Top::Import(import));
                if context.is_import_file_path_examined(&import_file_path) {
                    context.insert_error(import_span, "Duplicated import")
                } else {
                    context.add_examined_import_file(import_file_path);
                }
            },
            Rule::constant_statement => { // let a = 5
                let constant = parse_constant_statement(current, context);
                references.constants.insert(constant.id());
                tops.insert(constant.id(), Top::Constant(constant));
            },
            Rule::config_block => { // server { ... }
                let config = parse_config_block(current, context);
                references.configs.insert(config.id());
                context.schema_references.add_config(&config);
                tops.insert(config.id(), Top::Config(config));
            },
            Rule::model_declaration => { // model A { ... }
                let model = parse_model_declaration(current, context);
                references.models.insert(model.id());
                context.schema_references.models.push(model.path.clone());
                tops.insert(model.id(), Top::Model(model));
            },
            Rule::enum_declaration => { // enum A { ... }
                let r#enum = parse_enum_declaration(current, context);
                references.enums.insert(r#enum.id());
                context.schema_references.enums.push(r#enum.path.clone());
                tops.insert(r#enum.id(), Top::Enum(r#enum));
            },
            Rule::dataset_declaration => { // dataset a { ... }
                let data_set = parse_data_set_declaration(current, context);
                references.data_sets.insert(data_set.id());
                context.schema_references.data_sets.push(data_set.path.clone());
                tops.insert(data_set.id(), Top::DataSet(data_set));
            },
            Rule::interface_declaration => { // interface a { ... }
                let interface = parse_interface_declaration(current, context);
                references.interfaces.insert(interface.id());
                context.schema_references.interfaces.push(interface.path.clone());
                tops.insert(interface.id(), Top::Interface(interface));
            },
            Rule::namespace => {
                let namespace = parse_namespace(current, context);
                references.namespaces.insert(namespace.id());
                context.schema_references.namespaces.push(namespace.path.clone());
                tops.insert(namespace.id(), Top::Namespace(namespace));
            }
            // declares
            Rule::config_declaration => {
                let config_declaration = parse_config_declaration(current, context);
                references.config_declarations.insert(config_declaration.id());
                context.schema_references.config_declarations.push(config_declaration.path.clone());
                tops.insert(config_declaration.id(), Top::ConfigDeclaration(config_declaration));
            }
            Rule::decorator_declaration => {
                let decorator_declaration = parse_decorator_declaration(current, context);
                references.decorator_declarations.insert(decorator_declaration.id());
                context.schema_references.decorator_declarations.push(decorator_declaration.path.clone());
                tops.insert(decorator_declaration.id(), Top::DecoratorDeclaration(decorator_declaration));
            }
            Rule::pipeline_item_declaration => {
                let pipeline_item_declaration = parse_pipeline_item_declaration(current, context);
                references.pipeline_item_declarations.insert(pipeline_item_declaration.id());
                context.schema_references.pipeline_item_declarations.push(pipeline_item_declaration.path.clone());
                tops.insert(pipeline_item_declaration.id(), Top::PipelineItemDeclaration(pipeline_item_declaration));
            },
            Rule::middleware_declaration => {
                let middleware_declaration = parse_middleware(current, context);
                references.middlewares.insert(middleware_declaration.id());
                context.schema_references.middlewares.push(middleware_declaration.path.clone());
                tops.insert(middleware_declaration.id(), Top::Middleware(middleware_declaration));
            },
            Rule::action_group_declaration => {
                let action_group_declaration = parse_action_group_declaration(current, context);
                references.action_groups.insert(action_group_declaration.id());
                context.schema_references.action_groups.push(action_group_declaration.path.clone());
                tops.insert(action_group_declaration.id(), Top::ActionGroup(action_group_declaration));
            },
            Rule::struct_declaration => {
                let struct_declaration = parse_struct_declaration(current, context);
                references.action_groups.insert(struct_declaration.id());
                context.schema_references.struct_declarations.push(struct_declaration.path.clone());
                tops.insert(struct_declaration.id(), Top::StructDeclaration(struct_declaration));
            }
            Rule::CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => (),
        }
    }
    if builtin {
        context.schema_references.builtin_sources.push(id);
    }
    Source::new(
        id,
        if builtin { SourceType::Builtin } else { SourceType::Normal },
        path,
        tops,
        references
    )
}