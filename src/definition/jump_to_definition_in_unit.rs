use crate::ast::node::Node;
use crate::availability::Availability;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression;
use crate::r#type::r#type::Type;
use crate::search::search_unit_for_definition::search_unit_for_definition;
use crate::traits::identifiable::Identifiable;
use crate::traits::node_trait::NodeTrait;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn jump_to_definition_in_unit<'a>(
    schema: &'a Schema,
    source: &'a Source,
    unit: &'a Unit,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
    availability: Availability,
) -> Vec<Definition> {
    if unit.expressions.len() == 1 {
        jump_to_definition_in_expression(
            schema,
            source,
            unit.expressions().next().unwrap(),
            namespace_path,
            line_col,
            expect,
            availability,
        )
    } else {
        search_unit_for_definition(
            schema,
            source,
            unit,
            namespace_path,
            line_col,
            |_argument_list, _callable_container_path, _callable_name| {
                vec![]
            },
            |subscript| {
                if subscript.expression().span().contains_line_col(line_col) {
                    let exp = Type::Undetermined;
                    jump_to_definition_in_expression(
                        schema,
                        source,
                        subscript.expression(),
                        namespace_path,
                        line_col,
                        &exp,
                        availability,
                    )
                } else {
                    vec![]
                }
            },
            |span, identifier_container_path, identifier_name| {
                let top = schema.find_top_by_path(identifier_container_path).unwrap();
                match top {
                    Node::Config(config) => if let Some(identifier) = identifier_name {
                        let item = config.items().iter().find(|i| i.identifier().name() == identifier).unwrap();
                        vec![Definition {
                            path: schema.source(config.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: item.span,
                            identifier_span: item.identifier().span,
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(config.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: config.span,
                            identifier_span: config.identifier().map_or(config.keyword().span, |i| i.span),
                        }]
                    },
                    Node::ConfigDeclaration(config_declaration) => if let Some(identifier) = identifier_name {
                        let item = config_declaration.fields().find(|i| i.identifier().name() == identifier).unwrap();
                        vec![Definition {
                            path: schema.source(config_declaration.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: item.span,
                            identifier_span: item.identifier().span,
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(config_declaration.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: config_declaration.span,
                            identifier_span: config_declaration.identifier().span,
                        }]
                    },
                    Node::Constant(constant) => vec![Definition {
                        path: schema.source(constant.source_id()).unwrap().file_path.clone(),
                        selection_span: span,
                        target_span: constant.span,
                        identifier_span: constant.identifier().span,
                    }],
                    Node::Enum(r#enum) => if let Some(identifier) = identifier_name {
                        let member = r#enum.members().find(|m| m.identifier().name() == identifier).unwrap();
                        vec![Definition {
                            path: schema.source(member.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: member.span,
                            identifier_span: member.identifier().span,
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(r#enum.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: r#enum.span,
                            identifier_span: r#enum.identifier().span,
                        }]
                    },
                    Node::Model(model) => if let Some(identifier) = identifier_name {
                        let field = model.fields().find(|i| i.identifier().name() == identifier).unwrap();
                        vec![Definition {
                            path: schema.source(field.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: field.span,
                            identifier_span: field.identifier().span,
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(model.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: model.span,
                            identifier_span: model.identifier().span,
                        }]
                    },
                    Node::InterfaceDeclaration(interface) => if let Some(identifier) = identifier_name {
                        let field = interface.fields().find(|i| i.identifier().name() == identifier).unwrap();
                        vec![Definition {
                            path: schema.source(field.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: field.span,
                            identifier_span: field.identifier().span,
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(interface.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: interface.span,
                            identifier_span: interface.identifier().span,
                        }]
                    }
                    Node::Namespace(namespace) => if let Some(identifier) = identifier_name {
                        let top = namespace.find_top_by_name(identifier, &top_filter_for_reference_type(ReferenceSpace::Default), availability).unwrap();
                        vec![Definition {
                            path: schema.source(top.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: top.span(),
                            identifier_span: top.identifier_span().unwrap(),
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(namespace.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: namespace.span,
                            identifier_span: namespace.identifier().span,
                        }]
                    }
                    Node::StructDeclaration(struct_declaration) => if let Some(identifier) = identifier_name {
                        let method = struct_declaration.function_declarations().find(|f| f.identifier().name() == identifier).unwrap();
                        vec![Definition {
                            path: schema.source(method.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: method.span,
                            identifier_span: method.identifier().span,
                        }]
                    } else {
                        vec![Definition {
                            path: schema.source(struct_declaration.source_id()).unwrap().file_path.clone(),
                            selection_span: span,
                            target_span: struct_declaration.span,
                            identifier_span: struct_declaration.identifier().span,
                        }]
                    },
                    _ => vec![]
                }
            },
            vec![],
            availability,
        )
    }
}