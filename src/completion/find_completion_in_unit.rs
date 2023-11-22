use crate::ast::expression::ExpressionKind;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::completion::collect_argument_list_names::collect_argument_list_names_from_argument_list_declaration;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list::find_completion_in_argument_list;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::expr::{ExprInfo, ReferenceType};
use crate::r#type::Type;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn find_completion_in_unit(schema: &Schema, source: &Source, unit: &Unit, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    if unit.expressions().count() == 0 {
        return vec![];
    }
    let mut previous_resolved = &ExprInfo::undetermined();
    for (index, expression) in unit.expressions().enumerate() {
        if expression.span().contains_line_col(line_col) {
            if index == 0 {
                return find_completion_in_expression(
                    schema,
                    source,
                    expression,
                    line_col,
                    namespace_path,
                    availability,
                );
            } else {
                match &expression.kind {
                    ExpressionKind::ArgumentList(argument_list) => {
                        let mut names = vec![];
                        if let Some(reference_info) = previous_resolved.reference_info() {
                            match reference_info.r#type {
                                ReferenceType::StructInstanceFunction => {
                                    let struct_definition = schema.find_top_by_path(&reference_info.reference().path_without_last(1)).unwrap().as_struct_declaration().unwrap();
                                    let function_definition = struct_definition.instance_function(*reference_info.reference().str_path().last().unwrap()).unwrap();
                                    let argument_names = collect_argument_list_names_from_argument_list_declaration(function_definition.argument_list_declaration());
                                    names = vec![argument_names];
                                },
                                ReferenceType::StructStaticFunction => {
                                    let struct_definition = schema.find_top_by_path(&reference_info.reference().path_without_last(1)).unwrap().as_struct_declaration().unwrap();
                                    let function_definition = struct_definition.static_function(*reference_info.reference().str_path().last().unwrap()).unwrap();
                                    let argument_names = collect_argument_list_names_from_argument_list_declaration(function_definition.argument_list_declaration());
                                    names = vec![argument_names];
                                },
                                ReferenceType::EnumMember => {
                                    let enum_definition = schema.find_top_by_path(&reference_info.reference().path_without_last(1)).unwrap().as_enum().unwrap();
                                    let member_definition = enum_definition.members().find(|m| m.identifier().name() == *reference_info.reference().str_path().last().unwrap()).unwrap();
                                    if let Some(argument_list_declaration) = member_definition.argument_list_declaration() {
                                        let argument_names = collect_argument_list_names_from_argument_list_declaration(argument_list_declaration);
                                        names = vec![argument_names];
                                    }
                                },
                                _ => (),
                            }
                        }
                        return find_completion_in_argument_list(
                            schema,
                            source,
                            argument_list,
                            line_col,
                            namespace_path,
                            availability,
                            names,
                        );
                    },
                    ExpressionKind::Subscript(subscript) => if subscript.expression().span().contains_line_col(line_col) {
                        return find_completion_in_expression(schema, source, subscript.expression(), line_col, namespace_path, availability);
                    } else {
                        return vec![];
                    },
                    ExpressionKind::IntSubscript(_) => {
                        return if let Some(union) = previous_resolved.r#type().as_union() {
                            completion_items_from_union_types(union)
                        } else {
                            vec![]
                        };
                    },
                    ExpressionKind::Identifier(_) => {
                        return completion_items_in_unit_for_identifier_or_int_subscript_with_previous_resolved(
                            schema, source, previous_resolved, line_col, namespace_path, availability,
                        );
                    },
                    _ => unreachable!(),
                }
            }
        } else {
            previous_resolved = expression.resolved();
        }
    }
    if let Some(empty_dot) = unit.empty_dot() {
        if empty_dot.span.contains_line_col(line_col) {
            return completion_items_in_unit_for_identifier_or_int_subscript_with_previous_resolved(
                schema, source, previous_resolved, line_col, namespace_path, availability,
            );
        }
    }
    vec![]
}

fn completion_items_in_unit_for_identifier_or_int_subscript_with_previous_resolved(
    schema: &Schema,
    source: &Source,
    previous_resolved: &ExprInfo,
    line_col: (usize, usize),
    namespace_path: &Vec<&str>,
    availability: Availability,
) -> Vec<CompletionItem> {
    if let Some(reference_info) = previous_resolved.reference_info() {
        match reference_info.r#type() {
            ReferenceType::Config => {
                vec![]
            }
            ReferenceType::DictionaryField => {}
            ReferenceType::Constant => {}
            ReferenceType::Enum => {}
            ReferenceType::EnumMember => {}
            ReferenceType::Model => {}
            ReferenceType::ModelField => {}
            ReferenceType::Interface => {}
            ReferenceType::InterfaceField => {}
            ReferenceType::Middleware => {}
            ReferenceType::DataSet => {}
            ReferenceType::DataSetRecord => {}
            ReferenceType::DecoratorDeclaration => {}
            ReferenceType::PipelineItemDeclaration => {}
            ReferenceType::StructDeclaration => {}
            ReferenceType::StructInstanceFunction => {}
            ReferenceType::StructStaticFunction => {}
            ReferenceType::FunctionDeclaration => {}
            ReferenceType::Namespace => {}
        }
    } else {
        if let Some(struct_object) = previous_resolved.r#type().as_struct_object() {

        } else if let Some(tuple) = previous_resolved.r#type().as_tuple() {

        } else {
            vec![]
        }
    }
}

fn completion_items_from_union_types(union: &Vec<Type>) -> Vec<CompletionItem> {
    union.iter().enumerate().map(|(idx, t)| CompletionItem {
        label: format!("{}", idx + 1),
        namespace_path: Some(format!("{t}")),
        documentation: None,
        detail: None,
    }).collect()
}