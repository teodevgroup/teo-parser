use crate::ast::argument_list::ArgumentList;
use crate::availability::Availability;
use crate::ast::expression::ExpressionKind;
use crate::ast::node::Node;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::ast::subscript::Subscript;
use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;
use crate::search::search_identifier_path::{search_identifier_path_names_with_filter_to_path};
use crate::traits::identifiable::Identifiable;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_reference_type;

#[derive(Debug)]
pub enum UnitSearchResult {
    Type(Type),
    Reference(Vec<usize>),
}

impl UnitSearchResult {

    pub(super) fn is_reference(&self) -> bool {
        self.as_reference().is_some()
    }

    pub(super) fn as_reference(&self) -> Option<&Vec<usize>> {
        match self {
            Self::Reference(r) => Some(r),
            _ => None,
        }
    }

    pub(super) fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub(super) fn as_type(&self) -> Option<&Type> {
        match self {
            Self::Type(t) => Some(t),
            _ => None,
        }
    }
}

pub fn search_unit_for_definition<HAL, HS, HI, OUTPUT>(
    schema: &Schema,
    source: &Source,
    unit: &Unit,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    handle_argument_list: HAL,
    handle_subscript: HS,
    handle_identifier: HI,
    default: OUTPUT,
    availability: Availability,
) -> OUTPUT where
    HAL: Fn(&ArgumentList, &Vec<usize>, Option<&str>) -> OUTPUT,
    HS: Fn(&Subscript) -> OUTPUT,
    HI: Fn(Span, &Vec<usize>, Option<&str>) -> OUTPUT,
{
    let mut current: Option<UnitSearchResult> = None;
    for (index, expression) in unit.expressions().enumerate() {
        if index == 0 {
            let mut identifier_span = None;
            current = Some(if let Some(identifier) = expression.kind.as_identifier() {
                if let Some(path) = search_identifier_path_names_with_filter_to_path(
                    &vec![identifier.name()],
                    schema,
                    source,
                    namespace_path,
                    &top_filter_for_reference_type(ReferenceSpace::Default),
                    availability,
                ) {
                    identifier_span = Some(identifier.span);
                    UnitSearchResult::Reference(path)
                } else {
                    UnitSearchResult::Type(Type::Undetermined)
                }
            } else {
                UnitSearchResult::Type(expression.resolved().r#type().clone())
            });
            if expression.span().contains_line_col(line_col) {
                if let Some(current) = current {
                    return match current {
                        UnitSearchResult::Type(_) => default,
                        UnitSearchResult::Reference(path) => handle_identifier(identifier_span.unwrap(), &path, None),
                    }
                }
                break
            }
            if current.is_some() && current.as_ref().unwrap().is_reference() {
                let top = schema.find_top_by_path(current.as_ref().unwrap().as_reference().unwrap()).unwrap();
                if top.is_constant() {
                    current = Some(UnitSearchResult::Type(top.as_constant().unwrap().resolved().r#type.clone()));
                }
            }
        } else {
            if current.as_ref().is_some() {
                match current.as_ref().unwrap() {
                    UnitSearchResult::Type(current_type) => {
                        if let Some((reference, _)) = current_type.as_struct_object() {
                            match &expression.kind {
                                ExpressionKind::Identifier(_) => {
                                    return default
                                }
                                ExpressionKind::Subscript(subscript) => {
                                    let struct_declaration = schema.find_top_by_path(reference.path()).unwrap().as_struct_declaration().unwrap();
                                    if subscript.span.contains_line_col(line_col) {
                                        if subscript.expression().span().contains_line_col(line_col) {
                                            return handle_subscript(&subscript);
                                        } else {
                                            return default;
                                        }
                                    } else {
                                        if let Some(subscript_function) = struct_declaration.function_declarations().find(|f| {
                                            f.r#static == false && f.identifier().name() == "subscript"
                                        }) {
                                            current = Some(UnitSearchResult::Type(subscript_function.return_type().resolved().clone()));
                                        } else {
                                            return default;
                                        }
                                    }
                                }
                                _ => unreachable!(),
                            }
                        } else {
                            return default;
                        }
                    }
                    UnitSearchResult::Reference(current_reference) => {
                        match schema.find_top_by_path(&current_reference).unwrap() {
                            Node::StructDeclaration(struct_declaration) => {
                                match &expression.kind {
                                    ExpressionKind::ArgumentList(argument_list) => {
                                        if let Some(new) = struct_declaration.function_declarations().find(|f| f.r#static && f.identifier().name() == "new") {
                                            if argument_list.span.contains_line_col(line_col) {
                                                return handle_argument_list(argument_list, &struct_declaration.path, Some(new.identifier().name()));
                                            } else {
                                                current = Some(UnitSearchResult::Type(new.return_type().resolved().clone()));
                                            }
                                        } else {
                                            return default;
                                        }
                                    }
                                    ExpressionKind::Subscript(_s) => {
                                        return default;
                                    }
                                    ExpressionKind::Identifier(_i) => {
                                        return default;
                                    }
                                    _ => unreachable!()
                                }
                            },
                            Node::Config(config) => {
                                match &expression.kind {
                                    ExpressionKind::Identifier(identifier) => {
                                        if let Some(item) = config.items().find(|i| i.identifier().name() == identifier.name()) {
                                            if identifier.span.contains_line_col(line_col) {
                                                return handle_identifier(identifier.span, config.path.as_ref(), Some(item.identifier().name()));
                                            } else {
                                                current = Some(UnitSearchResult::Type(item.expression().resolved().r#type.clone()));
                                            }
                                        } else {
                                            return default;
                                        }
                                    },
                                    ExpressionKind::ArgumentList(_a) => {
                                        return default;
                                    }
                                    ExpressionKind::Subscript(_s) => {
                                        return default;
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Node::Enum(r#enum) => {
                                match &expression.kind {
                                    ExpressionKind::Identifier(i) => {
                                        if let Some(member) = r#enum.members().find(|m| m.identifier().name() == i.name()) {
                                            if i.span.contains_line_col(line_col) {
                                                return handle_identifier(i.span, r#enum.path.as_ref(), Some(member.identifier().name()));
                                            } else {
                                                return default;
                                            }
                                        } else {
                                            return default;
                                        }
                                    }
                                    ExpressionKind::ArgumentList(_a) => {
                                        return default;
                                    }
                                    ExpressionKind::Subscript(_s) => {
                                        return default;
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Node::Model(model) => {
                                match &expression.kind {
                                    ExpressionKind::Identifier(identifier) => {
                                        if let Some(field) = model.fields().find(|f| f.name() == identifier.name()) {
                                            if identifier.span.contains_line_col(line_col) {
                                                return handle_identifier(identifier.span, model.path.as_ref(), Some(field.name()));
                                            } else {
                                                return default;
                                            }
                                        } else {
                                            return default;
                                        }
                                    },
                                    ExpressionKind::ArgumentList(_a) => {
                                        return default;
                                    }
                                    ExpressionKind::Subscript(_s) => {
                                        return default;
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Node::InterfaceDeclaration(interface) => {
                                match &expression.kind {
                                    ExpressionKind::Identifier(identifier) => {
                                        if let Some(field) = interface.fields().find(|f| f.name() == identifier.name()) {
                                            if identifier.span.contains_line_col(line_col) {
                                                return handle_identifier(identifier.span, interface.path.as_ref(), Some(field.name()));
                                            } else {
                                                return default;
                                            }
                                        } else {
                                            return default;
                                        }
                                    },
                                    ExpressionKind::ArgumentList(_a) => {
                                        return default;
                                    }
                                    ExpressionKind::Subscript(_s) => {
                                        return default;
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Node::Namespace(namespace) => {
                                match &expression.kind {
                                    ExpressionKind::Identifier(identifier) => {
                                        if let Some(top) = namespace.find_top_by_name(identifier.name(), &top_filter_for_reference_type(ReferenceSpace::Default), availability) {
                                            if identifier.span.contains_line_col(line_col) {
                                                return handle_identifier(identifier.span, top.path(), None);
                                            } else {
                                                return default;
                                            }
                                        } else {
                                            return default;
                                        }
                                    },
                                    ExpressionKind::ArgumentList(_a) => {
                                        return default;
                                    }
                                    ExpressionKind::Subscript(_s) => {
                                        return default;
                                    }
                                    _ => unreachable!()
                                }
                            }
                            _ => unreachable!()
                        }
                    }
                }
            } else {
                return default
            }
        }
    }
    default
}
