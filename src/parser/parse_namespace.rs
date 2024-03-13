use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::namespace::{Namespace, NamespaceReferences};
use crate::ast::node::Node;
use crate::{parse_append, parse_insert_keyword, parse_insert_punctuation, parse_set_optional};
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_handler_group::{parse_handler_declaration, parse_handler_group_declaration};
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_config_block::parse_config_block;
use crate::parser::parse_config_declaration::parse_config_declaration;
use crate::parser::parse_constant_statement::parse_constant_statement;
use crate::parser::parse_data_set_declaration::parse_data_set_declaration;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_decorator_declaration::parse_decorator_declaration;
use crate::parser::parse_empty_decorator::parse_empty_decorator;
use crate::parser::parse_enum::parse_enum_declaration;
use crate::parser::parse_handler_template_declaration::parse_handler_template_declaration;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_interface_declaration::parse_interface_declaration;
use crate::parser::parse_middleware_declaration::parse_middleware_declaration;
use crate::parser::parse_model::parse_model_declaration;
use crate::parser::parse_pipeline_item_declaration::parse_pipeline_item_declaration;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_struct_declaration::parse_struct_declaration;
use crate::parser::parse_synthesized_shape_declaration::parse_synthesized_shape_declaration;
use crate::parser::parse_use_middlewares_block::parse_use_middlewares_block;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_namespace(pair: Pair<'_>, context: &ParserContext) -> Namespace {
    let span = parse_span(&pair);
    if context.current_availability_flag() != Availability::default() {
        context.insert_error(span, "namespace is placed in availability flag");
    }
    let path = context.next_parent_path();
    context.push_namespace_id(*path.last().unwrap());
    let mut comment = None;
    let mut identifier = 0;
    let mut string_path = vec![];
    let mut references = NamespaceReferences::new();
    let mut children = btreemap!{};
    let mut inside_block = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::NAMESPACE_KEYWORD => parse_insert_keyword!(context, current, children, "namespace"),
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                inside_block = true;
            },
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::identifier => {
                let node = parse_identifier(&current, context);
                identifier = node.id();
                if context.current_availability_flag() != Availability::default() {
                    context.insert_error(node.span, "namespace shouldn't be placed under availability flags")
                }
                if node.name() == "main" {
                    context.insert_error(node.span, "'main' is reserved for main namespace");
                } else if node.name() == "std" {
                    if !context.is_builtin_source() {
                        context.insert_error(node.span, "'std' is reserved for standard library");
                    }
                }
                string_path = context.next_parent_string_path(node.name());
                children.insert(node.id(), node.into());
            },
            Rule::constant_statement => { // let a = 5
                let constant = parse_constant_statement(current, context);
                references.constants.insert(constant.id());
                children.insert(constant.id(), Node::ConstantDeclaration(constant));
            },
            Rule::config_block => { // server { ... }
                let config = parse_config_block(current, context);
                references.configs.insert(config.id());
                context.schema_references_mut().add_config(&config);
                if config.keyword().is_connector() {
                    references.connector = Some(config.id());
                }
                children.insert(config.id(), Node::Config(config));
            },
            Rule::use_middlewares_block => { // middlewares [ ... ]
                let middlewares = parse_use_middlewares_block(current, context);
                references.use_middlewares_block = Some(middlewares.id());
                context.schema_references_mut().use_middlewares_blocks.push(middlewares.path.clone());
                children.insert(middlewares.id(), Node::UseMiddlewaresBlock(middlewares));
            },
            Rule::model_declaration => { // model A { ... }
                let model = parse_model_declaration(current, context);
                references.models.insert(model.id());
                context.schema_references_mut().models.push(model.path.clone());
                children.insert(model.id(), Node::Model(model));
            },
            Rule::enum_declaration => { // enum A { ... }
                let r#enum = parse_enum_declaration(current, context);
                references.enums.insert(r#enum.id());
                context.schema_references_mut().enums.push(r#enum.path.clone());
                children.insert(r#enum.id(), Node::Enum(r#enum));
            },
            Rule::dataset_declaration => { // dataset a { ... }
                let data_set = parse_data_set_declaration(current, context);
                references.data_sets.insert(data_set.id());
                context.schema_references_mut().data_sets.push(data_set.path.clone());
                children.insert(data_set.id(), Node::DataSet(data_set));
            },
            Rule::interface_declaration => { // interface a { ... }
                let interface = parse_interface_declaration(current, context);
                references.interfaces.insert(interface.id());
                context.schema_references_mut().interfaces.push(interface.path.clone());
                children.insert(interface.id(), Node::InterfaceDeclaration(interface));
            },
            Rule::namespace => {
                let namespace = parse_namespace(current, context);
                references.namespaces.insert(namespace.id());
                context.schema_references_mut().namespaces.push(namespace.path.clone());
                children.insert(namespace.id(), Node::Namespace(namespace));
            },
            Rule::config_declaration => {
                let config_declaration = parse_config_declaration(current, context);
                references.config_declarations.insert(config_declaration.id());
                context.schema_references_mut().config_declarations.push(config_declaration.path.clone());
                children.insert(config_declaration.id(), Node::ConfigDeclaration(config_declaration));
            },
            Rule::decorator_declaration => {
                let decorator_declaration = parse_decorator_declaration(current, context);
                references.decorator_declarations.insert(decorator_declaration.id());
                context.schema_references_mut().decorator_declarations.push(decorator_declaration.path.clone());
                children.insert(decorator_declaration.id(), Node::DecoratorDeclaration(decorator_declaration));
            }
            Rule::pipeline_item_declaration => {
                let pipeline_item_declaration = parse_pipeline_item_declaration(current, context);
                references.pipeline_item_declarations.insert(pipeline_item_declaration.id());
                context.schema_references_mut().pipeline_item_declarations.push(pipeline_item_declaration.path.clone());
                children.insert(pipeline_item_declaration.id(), Node::PipelineItemDeclaration(pipeline_item_declaration));
            },
            Rule::middleware_declaration => {
                let middleware_declaration = parse_middleware_declaration(current, context);
                references.middlewares.insert(middleware_declaration.id());
                context.schema_references_mut().middlewares.push(middleware_declaration.path.clone());
                children.insert(middleware_declaration.id(), Node::MiddlewareDeclaration(middleware_declaration));
            },
            Rule::handler_declaration => {
                let handler_declaration = parse_handler_declaration(current, context, false);
                references.handlers.insert(handler_declaration.id());
                context.schema_references_mut().handlers.push(handler_declaration.path().clone());
                children.insert(handler_declaration.id(), Node::HandlerDeclaration(handler_declaration));
            },
            Rule::handler_group_declaration => {
                let handler_group_declaration = parse_handler_group_declaration(current, context);
                references.handler_groups.insert(handler_group_declaration.id());
                context.schema_references_mut().handler_groups.push(handler_group_declaration.path.clone());
                children.insert(handler_group_declaration.id(), Node::HandlerGroupDeclaration(handler_group_declaration));
            },
            Rule::struct_declaration => {
                let struct_declaration = parse_struct_declaration(current, context);
                references.struct_declarations.insert(struct_declaration.id());
                context.schema_references_mut().struct_declarations.push(struct_declaration.path.clone());
                children.insert(struct_declaration.id(), Node::StructDeclaration(struct_declaration));
            },
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), children),
            Rule::empty_decorator => {
                let empty_decorator = parse_empty_decorator(current, context);
                references.empty_decorators.insert(empty_decorator.id());
                children.insert(empty_decorator.id(), Node::EmptyDecorator(empty_decorator));
            },
            Rule::decorator => {
                let unattached_decorator = parse_decorator(current, context);
                references.unattached_decorators.insert(unattached_decorator.id());
                children.insert(unattached_decorator.id(), Node::Decorator(unattached_decorator));
            },
            Rule::synthesized_shape_declaration => {
                let synthesized_shape_declaration = parse_synthesized_shape_declaration(current, context);
                references.synthesized_shape_declarations.insert(synthesized_shape_declaration.id());
                context.schema_references_mut().declared_shapes.push(synthesized_shape_declaration.path().clone());
                children.insert(synthesized_shape_declaration.id(), Node::SynthesizedShapeDeclaration(synthesized_shape_declaration));
            },
            Rule::handler_template_declaration => {
                let handler_template_declaration = parse_handler_template_declaration(current, context);
                references.handler_template_declarations.insert(handler_template_declaration.id());
                context.schema_references_mut().handler_templates.push(handler_template_declaration.path().clone());
                children.insert(handler_template_declaration.id(), Node::HandlerTemplateDeclaration(handler_template_declaration));
            },
            Rule::BLOCK_LEVEL_CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => (),
        }
    }
    context.pop_namespace_id();
    context.pop_parent_id();
    context.pop_string_path();
    Namespace {
        span,
        path,
        string_path,
        comment,
        identifier,
        children,
        references,
    }
}