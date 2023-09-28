use maplit::btreemap;
use crate::ast::namespace::{Namespace, NamespaceReferences};
use crate::ast::top::Top;
use crate::parser::parse_config_block::parse_config_block;
use crate::parser::parse_constant_statement::parse_constant_statement;
use crate::parser::parse_data_set_declaration::parse_data_set_declaration;
use crate::parser::parse_enum::parse_enum_declaration;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_interface_declaration::parse_interface_declaration;
use crate::parser::parse_model::parse_model_declaration;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_namespace(pair: Pair<'_>, context: &mut ParserContext) -> Namespace {
    let span = parse_span(&pair);
    let parent_path = context.current_path();
    let parent_string_path = context.current_string_path();
    let path = context.next_parent_path();
    let mut identifier = None;
    let mut string_path = None;
    let mut references = NamespaceReferences::new();
    let mut tops = btreemap!{};
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                context.next_string_path(identifier.as_ref().unwrap().name());
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
            },
            _ => (),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    Namespace {
        span,
        path,
        parent_path,
        string_path: string_path.unwrap(),
        parent_string_path,
        identifier: identifier.unwrap(),
        tops,
        references,
    }
}