use array_tool::vec::Shift;
use indexmap::{IndexMap, indexmap};
use crate::ast::availability::Availability;
use crate::ast::decorator::Decorator;
use crate::ast::field::Field;
use crate::ast::model::{Model, ModelShapeResolved};
use crate::ast::reference::ReferenceType;
use crate::r#type::Type;
use crate::r#type::shape_reference::ShapeReference;
use crate::resolver::resolver_context::ResolverContext;
use crate::shape::input::Input;
use crate::shape::r#static::{STATIC_WHERE_INPUT_FOR_TYPE, STATIC_WHERE_WITH_AGGREGATES_INPUT_FOR_TYPE};
use crate::shape::shape::Shape;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_model_shapes<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    let mut model_shape_resolved = ModelShapeResolved::new();
    // select
    if let Some(input) = resolve_model_select_shape(model) {
        model_shape_resolved.map.insert("Select".to_owned(), input);
    }
    // include
    if let Some(input) = resolve_model_include_shape(model) {
        model_shape_resolved.map.insert("Include".to_owned(), input);
    }
    // where input
    if let Some(input) = resolve_model_where_input_shape(model, true, false) {
        model_shape_resolved.map.insert("WhereInput".to_owned(), input);
    }
    // where unique input
    if let Some(input) = resolve_model_where_unique_input_shape(model) {
        model_shape_resolved.map.insert("WhereUniqueInput".to_owned(), input);
    }
    // scalar where with aggregates input
    if let Some(input) = resolve_model_where_input_shape(model, false, true) {
        model_shape_resolved.map.insert("ScalarWhereWithAggregatesInput".to_owned(), input);
    }
    if model_shape_resolved.map.contains_key("WhereInput") {
        // relation filter
        model_shape_resolved.map.insert("RelationFilter".to_owned(), resolve_model_relation_filter(model));
        // list relation filter
        model_shape_resolved.map.insert("ListRelationFilter".to_owned(), resolve_model_list_relation_filter(model));
    }
    // order by input
    if let Some(input) = resolve_model_order_by_input_shape(model, context) {
        model_shape_resolved.map.insert("OrderByInput".to_owned(), input);
    }

    model.shape_resolve(model_shape_resolved);
}

fn resolve_model_select_shape(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(field_settings) = field.resolved().class.as_model_primitive_field() {
            if !field_settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_getter(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_model_include_shape(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(_) = field.resolved().class.as_model_relation() {
            if let Some((related_model_path, related_model_string_path)) = field.type_expr.resolved().unwrap_optional().unwrap_array().as_model_object() {
                if relation_is_many(field) {
                    // many
                    map.insert(
                        field.name().to_owned(),
                        Input::Type(Type::ShapeReference(ShapeReference::FindManyArgs(related_model_path.clone(), related_model_string_path.clone())).to_optional())
                    );
                } else {
                    // single
                    map.insert(
                        field.name().to_owned(),
                        Input::Type(Type::ShapeReference(ShapeReference::Args(related_model_path.clone(), related_model_string_path.clone())).to_optional())
                    );
                }
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_model_where_input_shape(model: &Model, include_relations: bool, with_aggregates: bool) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && is_field_queryable(field) && !is_field_writeonly(field) {
                if with_aggregates {
                    if let Some(where_input_type) = field_where_with_aggregates_input_for_type(field.type_expr.resolved()) {
                        map.insert(field.name().to_owned(), where_input_type.clone());
                    }
                } else {
                    if let Some(where_input_type) = field_where_input_for_type(field.type_expr.resolved()) {
                        map.insert(field.name().to_owned(), where_input_type.clone());
                    }
                }
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached && is_field_queryable(field) {
                if with_aggregates {
                    if let Some(where_input_type) = field_where_with_aggregates_input_for_type(field.type_expr.resolved()) {
                        map.insert(field.name().to_owned(), where_input_type.clone());
                    }
                } else {
                    if let Some(where_input_type) = field_where_input_for_type(field.type_expr.resolved()) {
                        map.insert(field.name().to_owned(), where_input_type.clone());
                    }
                }
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            if include_relations {
                if let Some((related_model_path, related_model_string_path)) = field.type_expr.resolved().unwrap_optional().unwrap_array().as_model_object() {
                    if relation_is_many(field) {
                        // many
                        map.insert(
                            field.name().to_owned(),
                            Input::Type(Type::ShapeReference(ShapeReference::ListRelationFilter(related_model_path.clone(), related_model_string_path.clone())).to_optional())
                        );
                    } else {
                        // single
                        map.insert(
                            field.name().to_owned(),
                            Input::Type(Type::ShapeReference(ShapeReference::RelationFilter(related_model_path.clone(), related_model_string_path.clone())).to_optional())
                        );
                    }
                }
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        // insert the three ops
        map.insert("AND".to_owned(), Input::Type(
            Type::ShapeReference(
                ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())
            ).wrap_in_array().to_optional()
        ));
        map.insert("OR".to_owned(), Input::Type(
            Type::ShapeReference(
                ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())
            ).wrap_in_array().to_optional()
        ));
        map.insert("NOT".to_owned(), Input::Type(
            Type::ShapeReference(
                ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())
            ).to_optional()
        ));
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_model_where_unique_input_shape(model: &Model) -> Option<Input> {
    let mut inputs = vec![];
    for decorator in &model.decorators {
        if decorator_has_any_name(decorator, vec!["id", "unique"]) {
            if let Some(argument_list) = &decorator.argument_list {
                if let Some(argument) = argument_list.arguments.first() {
                    if let Some(array_literal) = argument.value.kind.as_array_literal() {
                        let mut map = indexmap! {};
                        for expression in &array_literal.expressions {
                            if let Some(enum_variant_literal) = expression.kind.as_enum_variant_literal() {
                                let name = enum_variant_literal.identifier.name();
                                if let Some(field) = model.fields.iter().find(|f| f.identifier.name() == name) {
                                    map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().clone()));
                                }
                            }
                        }
                        if !map.is_empty() {
                            inputs.push(Input::Shape(Shape::new(map)));
                        }
                    }
                }
            }
        }
    }
    for field in &model.fields {
        for decorator in &field.decorators {
            if decorator_has_any_name(decorator, vec!["id", "unique"]) {
                inputs.push(Input::Shape(Shape::new(indexmap! {
                    field.name().to_owned() => Input::Type(field.type_expr.resolved().clone())
                })));
            }
        }
    }
    if inputs.is_empty() {
        None
    } else {
        Some(Input::Or(inputs))
    }
}

fn resolve_model_relation_filter(model: &Model) -> Input {
    let mut map = indexmap! {};
    map.insert("is".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    map.insert("isNot".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    Input::Shape(Shape::new(map))
}

fn resolve_model_list_relation_filter(model: &Model) -> Input {
    let mut map = indexmap! {};
    map.insert("every".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    map.insert("some".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    map.insert("none".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    Input::Shape(Shape::new(map))
}

fn resolve_model_order_by_input_shape<'a>(model: &'a Model, context: &'a ResolverContext<'a>) -> Option<Input> {
    let sort = context.schema.builtin_sources().get(0).unwrap().find_top_by_string_path(&vec!["std", "Sort"], &top_filter_for_reference_type(ReferenceType::Default), Availability::default()).unwrap().as_enum().unwrap();
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && is_field_sortable(field) && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::EnumVariant(sort.path.clone(), sort.string_path.clone())));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached && is_field_sortable(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::EnumVariant(sort.path.clone(), sort.string_path.clone())));
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn relation_is_many(field: &Field) -> bool {
    field.type_expr.resolved().unwrap_optional().is_array()
}

fn has_property_setter(field: &Field) -> bool {
    field_has_decorator_name(field, "setter")
}

fn has_property_getter(field: &Field) -> bool {
    field_has_decorator_name(field, "getter")
}

fn is_field_writeonly(field: &Field) -> bool {
    field_has_decorator_name(field, "writeonly")
}

fn is_field_readonly(field: &Field) -> bool {
    field_has_decorator_name(field, "readonly")
}

fn is_field_queryable(field: &Field) -> bool {
    !field_has_decorator_name(field, "unqueryable")
}

fn is_field_sortable(field: &Field) -> bool {
    !field_has_decorator_name(field, "unsortable")
}

fn field_has_decorator_name(field: &Field, name: &str) -> bool {
    field_has_decorator(field, |names| names == vec![name])
}

fn field_has_decorator<F>(field: &Field, f: F) -> bool where F: Fn(Vec<&str>) -> bool {
    for decorator in &field.decorators {
        let names = if *decorator.identifier_path.names().first().unwrap() == "std" {
            let mut result = decorator.identifier_path.names();
            result.shift();
            result
        } else {
            decorator.identifier_path.names()
        };
        if f(names) {
            return true
        }
    }
    false
}

fn decorator_has_any_name(decorator: &Decorator, names: Vec<&str>) -> bool {
    let mut names = decorator.identifier_path.names();
    if *names.first().unwrap() == "std" {
        names.shift();
    }
    if names.len() != 1 {
        return false;
    }
    let name = *names.last().unwrap();
    names.contains(&name)
}

fn field_where_with_aggregates_input_for_type(t: &Type) -> Option<Input> {
    if let Some((a, b)) = t.unwrap_optional().as_enum_variant() {
        if t.is_optional() {
            Some(Input::Type(Type::Union(vec![
                Type::EnumVariant(a.clone(), b.clone()),
                Type::Null,
                Type::ShapeReference(ShapeReference::EnumNullableWithAggregatesFilter(Box::new(t.unwrap_optional().clone()))),
            ]).to_optional()))
        } else {
            Some(Input::Type(Type::Union(vec![
                Type::EnumVariant(a.clone(), b.clone()),
                Type::ShapeReference(ShapeReference::EnumWithAggregatesFilter(Box::new(t.clone()))),
            ]).to_optional()))
        }
    } else if let Some(inner) = t.unwrap_optional().as_array() {
        if t.is_optional() {
            Some(Input::Type(Type::Union(vec![
                t.unwrap_optional().clone(),
                Type::Null,
                Type::ShapeReference(ShapeReference::ArrayNullableWithAggregatesFilter(Box::new(inner.clone()))),
            ])))
        } else {
            Some(Input::Type(Type::Union(vec![
                t.clone(),
                Type::ShapeReference(ShapeReference::ArrayWithAggregatesFilter(Box::new(inner.clone()))),
            ])))
        }
    } else {
        STATIC_WHERE_WITH_AGGREGATES_INPUT_FOR_TYPE.get(t).cloned()
    }
}

fn field_where_input_for_type<'a>(t: &Type) -> Option<Input> {
    if let Some((a, b)) = t.unwrap_optional().as_enum_variant() {
        if t.is_optional() {
            Some(Input::Type(Type::Union(vec![
                Type::EnumVariant(a.clone(), b.clone()),
                Type::Null,
                Type::ShapeReference(ShapeReference::EnumNullableFilter(Box::new(t.unwrap_optional().clone()))),
            ]).to_optional()))
        } else {
            Some(Input::Type(Type::Union(vec![
                Type::EnumVariant(a.clone(), b.clone()),
                Type::ShapeReference(ShapeReference::EnumFilter(Box::new(t.clone()))),
            ]).to_optional()))
        }
    } else if let Some(inner) = t.unwrap_optional().as_array() {
        if t.is_optional() {
            Some(Input::Type(Type::Union(vec![
                t.unwrap_optional().clone(),
                Type::Null,
                Type::ShapeReference(ShapeReference::ArrayNullableFilter(Box::new(inner.clone()))),
            ])))
        } else {
            Some(Input::Type(Type::Union(vec![
                t.clone(),
                Type::ShapeReference(ShapeReference::ArrayFilter(Box::new(inner.clone()))),
            ])))
        }
    } else {
        STATIC_WHERE_INPUT_FOR_TYPE.get(t).cloned()
    }
}