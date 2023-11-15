use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::namespace::{Namespace, NamespaceReferences};
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_handler_group::parse_handler_group_declaration;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_config_block::parse_config_block;
use crate::parser::parse_config_declaration::parse_config_declaration;
use crate::parser::parse_constant_statement::parse_constant_statement;
use crate::parser::parse_data_set_declaration::parse_data_set_declaration;
use crate::parser::parse_decorator_declaration::parse_decorator_declaration;
use crate::parser::parse_enum::parse_enum_declaration;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_interface_declaration::parse_interface_declaration;
use crate::parser::parse_middleware_declaration::parse_middleware_declaration;
use crate::parser::parse_model::parse_model_declaration;
use crate::parser::parse_pipeline_item_declaration::parse_pipeline_item_declaration;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_struct_declaration::parse_struct_declaration;
use crate::parser::parse_use_middlewares_block::parse_use_middlewares_block;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_namespace(pair: Pair<'_>, context: &mut ParserContext) -> Namespace {
    let span = parse_span(&pair);
    let path = context.next_parent_path();
    let mut comment = None;
    let mut identifier = None;
    let mut string_path = None;
    let mut references = NamespaceReferences::new();
    let mut tops = btreemap!{};
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => comment = Some(parse_doc_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                if context.current_availability_flag() != Availability::default() {
                    context.insert_error(identifier.as_ref().unwrap().span, "namespace shouldn't be placed under availability flags")
                }
                if identifier.as_ref().unwrap().name() == "main" {
                    context.insert_error(identifier.as_ref().unwrap().span, "'main' is reserved for main namespace");
                } else if identifier.as_ref().unwrap().name() == "std" {
                    if !context.is_builtin_source() {
                        context.insert_error(identifier.as_ref().unwrap().span, "'std' is reserved for standard library");
                    }
                }
                string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name()));
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
                if config.keyword.is_connector() {
                    references.connector = Some(config.id());
                }
                tops.insert(config.id(), Top::Config(config));
            },
            Rule::use_middlewares_block => { // middlewares [ ... ]
                let middlewares = parse_use_middlewares_block(current, context);
                references.use_middlewares_block = Some(middlewares.id());
                context.schema_references.use_middlewares_blocks.push(middlewares.path.clone());
                tops.insert(middlewares.id(), Top::UseMiddlewareBlock(middlewares));
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
            },
            Rule::config_declaration => {
                let config_declaration = parse_config_declaration(current, context);
                references.config_declarations.insert(config_declaration.id());
                context.schema_references.config_declarations.push(config_declaration.path.clone());
                tops.insert(config_declaration.id(), Top::ConfigDeclaration(config_declaration));
            },
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
                let middleware_declaration = parse_middleware_declaration(current, context);
                references.middlewares.insert(middleware_declaration.id());
                context.schema_references.middlewares.push(middleware_declaration.path.clone());
                tops.insert(middleware_declaration.id(), Top::Middleware(middleware_declaration));
            },
            Rule::handler_group_declaration => {
                let handler_group_declaration = parse_handler_group_declaration(current, context);
                references.handler_groups.insert(handler_group_declaration.id());
                context.schema_references.handler_groups.push(handler_group_declaration.path.clone());
                tops.insert(handler_group_declaration.id(), Top::HandlerGroup(handler_group_declaration));
            },
            Rule::struct_declaration => {
                let struct_declaration = parse_struct_declaration(current, context);
                references.struct_declarations.insert(struct_declaration.id());
                context.schema_references.struct_declarations.push(struct_declaration.path.clone());
                tops.insert(struct_declaration.id(), Top::StructDeclaration(struct_declaration));
            },
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), chilren),
            Rule::BLOCK_LEVEL_CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => (),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    Namespace {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        identifier: identifier.unwrap(),
        tops,
        references,
    }
}