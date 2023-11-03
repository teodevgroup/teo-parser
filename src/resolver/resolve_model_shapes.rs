use array_tool::vec::Shift;
use indexmap::indexmap;
use maplit::btreemap;
use crate::ast::arith::ArithExpr;
use crate::ast::availability::Availability;
use crate::ast::decorator::Decorator;
use crate::ast::expression::ExpressionKind;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::model::{Model, ModelShapeResolved};
use crate::ast::reference::ReferenceType;
use crate::ast::unit::Unit;
use crate::r#type::Type;
use crate::r#type::shape_reference::ShapeReference;
use crate::resolver::resolve_identifier::resolve_identifier;
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;
use crate::search::search_identifier_path::search_identifier_path_in_source;
use crate::shape::input::Input;
use crate::shape::r#static::{STATIC_UPDATE_INPUT_FOR_TYPE, STATIC_WHERE_INPUT_FOR_TYPE, STATIC_WHERE_WITH_AGGREGATES_INPUT_FOR_TYPE};
use crate::shape::shape::Shape;
use crate::shape::synthesized_enum::{SynthesizedEnum, SynthesizedEnumMember};
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_model_shapes<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    let mut model_shape_resolved = ModelShapeResolved::new();
    let mut shape_available_context = ShapeAvailableContext::new(); 
    // select
    if let Some(input) = resolve_model_select_shape(model) {
        model_shape_resolved.map.insert("Select".to_owned(), input);
        shape_available_context.has_select = true;
    }
    // include
    if let Some(input) = resolve_model_include_shape(model) {
        model_shape_resolved.map.insert("Include".to_owned(), input);
        shape_available_context.has_include = true;
    }
    // where input
    if let Some(input) = resolve_model_where_input_shape(model, true, false) {
        model_shape_resolved.map.insert("WhereInput".to_owned(), input);
        shape_available_context.has_where = true;
    }
    // where unique input
    if let Some(input) = resolve_model_where_unique_input_shape(model) {
        model_shape_resolved.map.insert("WhereUniqueInput".to_owned(), input);
        shape_available_context.has_where_unique = true;
    }
    // scalar where with aggregates input
    if let Some(input) = resolve_model_where_input_shape(model, false, true) {
        model_shape_resolved.map.insert("ScalarWhereWithAggregatesInput".to_owned(), input);
        shape_available_context.has_where_with_aggregates = true;
    }
    if shape_available_context.has_where {
        // relation filter
        model_shape_resolved.map.insert("RelationFilter".to_owned(), resolve_model_relation_filter(model));
        // list relation filter
        model_shape_resolved.map.insert("ListRelationFilter".to_owned(), resolve_model_list_relation_filter(model));
    }
    // order by input
    if let Some(input) = resolve_model_order_by_input_shape(model, context) {
        model_shape_resolved.map.insert("OrderByInput".to_owned(), input);
        shape_available_context.has_order_by = true;
    }
    // scalar field enum
    if let Some(input) = resolve_scalar_field_enum(model) {
        model_shape_resolved.map.insert("ScalarFieldEnum".to_owned(), input);
        shape_available_context.has_scalar_field_enum = true;
    }
    // count aggregate input type
    if let Some(input) = resolve_count_aggregate_input_type(model) {
        model_shape_resolved.map.insert("CountAggregateInputType".to_owned(), input);
    }
    // sum aggregate input type
    if let Some(input) = resolve_sum_aggregate_input_type(model) {
        model_shape_resolved.map.insert("SumAggregateInputType".to_owned(), input);
        shape_available_context.has_sum_aggregate = true;
    }
    // avg aggregate input type
    if let Some(input) = resolve_avg_aggregate_input_type(model) {
        model_shape_resolved.map.insert("AvgAggregateInputType".to_owned(), input);
        shape_available_context.has_avg_aggregate = true;
    }
    // min aggregate input type
    if let Some(input) = resolve_min_aggregate_input_type(model) {
        model_shape_resolved.map.insert("MinAggregateInputType".to_owned(), input);
        shape_available_context.has_min_aggregate = true;
    }
    // max aggregate input type
    if let Some(input) = resolve_max_aggregate_input_type(model) {
        model_shape_resolved.map.insert("MaxAggregateInputType".to_owned(), input);
        shape_available_context.has_max_aggregate = true;
    }
    // create input
    if let Some(input) = resolve_create_input_type(model, None, context) {
        model_shape_resolved.map.insert("CreateInput".to_owned(), input);
    }
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            if let Some(input) = resolve_create_input_type(model, Some(field.name()), context) {
                model_shape_resolved.without_map.insert(("CreateInput".to_owned(), field.name().to_owned()), input);
            }
        }
    }
    // update input
    if let Some(input) = resolve_update_input_type(model, None, context) {
        model_shape_resolved.map.insert("UpdateInput".to_owned(), input);
    }
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            if let Some(input) = resolve_update_input_type(model, Some(field.name()), context) {
                model_shape_resolved.without_map.insert(("UpdateInput".to_owned(), field.name().to_owned()), input);
            }
        }
    }
    // create nested one input
    model_shape_resolved.map.insert("CreateNestedOneInput".to_owned(), resolve_create_nested_one_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("CreateNestedOneInput".to_owned(), field.name().to_owned()), resolve_create_nested_one_input_type(model, Some(field.name())));
        }
    }
    // create nested many input
    model_shape_resolved.map.insert("CreateNestedManyInput".to_owned(), resolve_create_nested_many_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("CreateNestedManyInput".to_owned(), field.name().to_owned()), resolve_create_nested_many_input_type(model, Some(field.name())));
        }
    }
    // update nested one input
    model_shape_resolved.map.insert("UpdateNestedOneInput".to_owned(), resolve_update_nested_one_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("UpdateNestedOneInput".to_owned(), field.name().to_owned()), resolve_update_nested_one_input_type(model, Some(field.name())));
        }
    }
    // update nested many input
    model_shape_resolved.map.insert("UpdateNestedManyInput".to_owned(), resolve_update_nested_many_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("UpdateNestedManyInput".to_owned(), field.name().to_owned()), resolve_update_nested_many_input_type(model, Some(field.name())));
        }
    }
    // connect or create input
    model_shape_resolved.map.insert("ConnectOrCreateInput".to_owned(), resolve_connect_or_create_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("ConnectOrCreateInput".to_owned(), field.name().to_owned()), resolve_connect_or_create_input_type(model, Some(field.name())));
        }
    }
    // update with where unique input
    model_shape_resolved.map.insert("UpdateWithWhereUniqueInput".to_owned(), resolve_update_with_where_unique_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("UpdateWithWhereUniqueInput".to_owned(), field.name().to_owned()), resolve_update_with_where_unique_input_type(model, Some(field.name())));
        }
    }
    // upsert with where unique input
    model_shape_resolved.map.insert("UpsertWithWhereUniqueInput".to_owned(), resolve_upsert_with_where_unique_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("UpsertWithWhereUniqueInput".to_owned(), field.name().to_owned()), resolve_upsert_with_where_unique_input_type(model, Some(field.name())));
        }
    }
    // update many with where input
    model_shape_resolved.map.insert("UpdateManyWithWhereInput".to_owned(), resolve_update_many_with_where_input_type(model, None));
    for field in &model.fields {
        if field.resolved().class.as_model_relation().is_some() {
            model_shape_resolved.without_map.insert(("UpdateManyWithWhereInput".to_owned(), field.name().to_owned()), resolve_update_many_with_where_input_type(model, Some(field.name())));
        }
    }
    // result
    model_shape_resolved.map.insert("Result".to_owned(), resolve_result_type(model));
    // count aggregate result
    model_shape_resolved.map.insert("CountAggregateResult".to_owned(), resolve_count_aggregate_result_type(model));
    // sum aggregate result
    if let Some(input) = resolve_sum_aggregate_result_type(model) {
        model_shape_resolved.map.insert("SumAggregateResult".to_owned(), input);
    }
    // avg aggregate result
    if let Some(input) = resolve_avg_aggregate_result_type(model) {
        model_shape_resolved.map.insert("AvgAggregateResult".to_owned(), input);
    }
    // min aggregate result
    if let Some(input) = resolve_min_aggregate_result_type(model) {
        model_shape_resolved.map.insert("MinAggregateResult".to_owned(), input);
    }
    // max aggregate result
    if let Some(input) = resolve_max_aggregate_result_type(model) {
        model_shape_resolved.map.insert("MaxAggregateResult".to_owned(), input);
    }
    // aggregate result
    model_shape_resolved.map.insert("AggregateResult".to_owned(), resolve_aggregate_result_type(model, &shape_available_context));
    // group by result
    model_shape_resolved.map.insert("GroupByResult".to_owned(), resolve_group_by_result_type(model, &shape_available_context));
    // args
    if shape_available_context.has_args() {
        model_shape_resolved.map.insert("Args".to_owned(), resolve_args_type(model, &shape_available_context));
    }
    // find many args
    model_shape_resolved.map.insert("FindManyArgs".to_owned(), resolve_find_many_args_type(model, &shape_available_context));
    // find first args
    model_shape_resolved.map.insert("FindFirstArgs".to_owned(), resolve_find_first_args_type(model, &shape_available_context));
    // find unique args
    model_shape_resolved.map.insert("FindUniqueArgs".to_owned(), resolve_find_unique_args_type(model, &shape_available_context));
    // create args
    model_shape_resolved.map.insert("CreateArgs".to_owned(), resolve_create_args_type(model, &shape_available_context));
    // update args
    model_shape_resolved.map.insert("UpdateArgs".to_owned(), resolve_update_args_type(model, &shape_available_context));
    // upsert args
    model_shape_resolved.map.insert("UpsertArgs".to_owned(), resolve_upsert_args_type(model, &shape_available_context));
    // copy args
    model_shape_resolved.map.insert("CopyArgs".to_owned(), resolve_copy_args_type(model, &shape_available_context));
    // delete args
    model_shape_resolved.map.insert("DeleteArgs".to_owned(), resolve_delete_args_type(model));
    // create many args
    model_shape_resolved.map.insert("CreateManyArgs".to_owned(), resolve_create_many_args_type(model, &shape_available_context));
    // update many args
    model_shape_resolved.map.insert("UpdateManyArgs".to_owned(), resolve_update_many_args_type(model, &shape_available_context));
    // delete many args
    model_shape_resolved.map.insert("DeleteManyArgs".to_owned(), resolve_delete_many_args_type(model));
    // copy many args
    model_shape_resolved.map.insert("CopyManyArgs".to_owned(), resolve_copy_many_args_type(model, &shape_available_context));
    // count args
    model_shape_resolved.map.insert("CountArgs".to_owned(), resolve_count_args_type(model, &shape_available_context));
    // aggregate args
    model_shape_resolved.map.insert("AggregateArgs".to_owned(), resolve_aggregate_args_type(model, &shape_available_context));
    // group by args
    model_shape_resolved.map.insert("GroupByArgs".to_owned(), resolve_group_by_args_type(model, &shape_available_context));

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

fn resolve_scalar_field_enum(model: &Model) -> Option<Input> {
    let mut members = vec![];
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment.clone(),
                });
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment.clone(),
                });
            }
        }
    }
    if !members.is_empty() {
        Some(Input::SynthesizedEnum(SynthesizedEnum::new(members)))
    } else {
        None
    }
}

fn resolve_count_aggregate_input_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        }
    }
    map.insert("_all".to_owned(), Input::Type(Type::Bool.to_optional()));
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_sum_aggregate_input_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr.resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr.resolved().is_any_number() && settings.cached {
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

fn resolve_avg_aggregate_input_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr.resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr.resolved().is_any_number() && settings.cached {
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

fn resolve_min_aggregate_input_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
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

fn resolve_max_aggregate_input_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool.to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
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

fn resolve_create_input_type<'a>(model: &'a Model, without: Option<&str>, context: &'a ResolverContext<'a>) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_readonly(field) {
                let optional = is_field_input_omissible(field) || field_has_on_save(field) || field_has_default(field);
                let mut t = field.type_expr.resolved().clone();
                if optional {
                    t = t.to_optional();
                }
                map.insert(field.name().to_owned(), Input::Type(t));
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_setter(field) {
                let optional = is_field_input_omissible(field);
                let mut t = field.type_expr.resolved().clone();
                if optional {
                    t = t.to_optional();
                }
                map.insert(field.name().to_owned(), Input::Type(t));
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            if let Some(without) = without {
                if field.name() == without {
                    continue
                }
            }
            let that_model = field.type_expr.resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object()?;
            if relation_is_many(field) {
                if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::CreateNestedManyInputWithout(that_model.0.clone(), that_model.1.clone(), opposite_relation_field.name().to_owned())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
                } else {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::CreateNestedManyInput(that_model.0.clone(), that_model.1.clone())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
                }
            } else {
                if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::CreateNestedOneInputWithout(that_model.0.clone(), that_model.1.clone(), opposite_relation_field.name().to_owned())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
                } else {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::CreateNestedOneInput(that_model.0.clone(), that_model.1.clone())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
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

fn resolve_update_input_type<'a>(model: &'a Model, without: Option<&str>, context: &'a ResolverContext<'a>) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_readonly(field) {
                if let Some(input) = field_update_input_for_type(field.type_expr.resolved(), is_field_atomic(field)) {
                    map.insert(field.name().to_owned(), input);
                }
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_setter(field) {
                if let Some(input) = field_update_input_for_type(field.type_expr.resolved(), false) {
                    map.insert(field.name().to_owned(), input);
                }
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            if let Some(without) = without {
                if field.name() == without {
                    continue
                }
            }
            let that_model = field.type_expr.resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object()?;
            if relation_is_many(field) {
                if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::UpdateNestedManyInputWithout(that_model.0.clone(), that_model.1.clone(), opposite_relation_field.name().to_owned())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
                } else {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::UpdateNestedManyInput(that_model.0.clone(), that_model.1.clone())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
                }
            } else {
                if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::UpdateNestedOneInputWithout(that_model.0.clone(), that_model.1.clone(), opposite_relation_field.name().to_owned())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
                } else {
                    let t = Input::Type(
                        Type::ShapeReference(ShapeReference::UpdateNestedOneInput(that_model.0.clone(), that_model.1.clone())).to_optional()
                    );
                    map.insert(field.name().to_owned(), t);
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

fn resolve_create_nested_one_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::CreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())
    }).to_optional()));
    map.insert("connectOrCreate".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::ConnectOrCreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::ConnectOrCreateInput(model.path.clone(), model.string_path.clone())
    }).to_optional()));
    map.insert("connect".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_create_nested_many_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::CreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("connectOrCreate".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::ConnectOrCreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::ConnectOrCreateInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("connect".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_enumerable().to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_update_nested_one_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::CreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())
    }).to_optional()));
    map.insert("connectOrCreate".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::ConnectOrCreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::ConnectOrCreateInput(model.path.clone(), model.string_path.clone())
    }).to_optional()));
    map.insert("connect".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("set".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpdateWithWhereUniqueInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpdateWithWhereUniqueInput(model.path.clone(), model.string_path.clone())
    }).to_optional()));
    map.insert("upsert".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpsertWithWhereUniqueInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpsertWithWhereUniqueInput(model.path.clone(), model.string_path.clone())
    }).to_optional()));
    map.insert("disconnect".to_owned(), Input::Type(Type::Bool.to_optional()));
    map.insert("delete".to_owned(), Input::Type(Type::Bool.to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_update_nested_many_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::CreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("connectOrCreate".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::ConnectOrCreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::ConnectOrCreateInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("connect".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_enumerable().to_optional()));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpdateWithWhereUniqueInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpdateWithWhereUniqueInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("upsert".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpsertWithWhereUniqueInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpsertWithWhereUniqueInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("disconnect".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_enumerable().to_optional()));
    map.insert("delete".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_enumerable().to_optional()));
    map.insert("updateMany".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpdateManyWithWhereInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpdateManyWithWhereInput(model.path.clone(), model.string_path.clone())
    }).to_enumerable().to_optional()));
    map.insert("deleteMany".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())).to_enumerable().to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_connect_or_create_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::CreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())
    })));
    Input::Shape(Shape::new(map))
}

fn resolve_update_with_where_unique_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpdateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone())
    })));
    Input::Shape(Shape::new(map))
}

fn resolve_upsert_with_where_unique_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::CreateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())
    })));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpdateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone())
    })));
    Input::Shape(Shape::new(map))
}

fn resolve_update_many_with_where_input_type(model: &Model, without: Option<&str>) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(if let Some(without) = without {
        ShapeReference::UpdateInputWithout(model.path.clone(), model.string_path.clone(), without.to_owned())
    } else {
        ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone())
    })));
    Input::Shape(Shape::new(map))
}

fn resolve_result_type(model: &Model) -> Input {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(if is_field_output_omissible(field) {
                    field.type_expr.resolved().to_optional()
                } else {
                    field.type_expr.resolved().clone()
                }));
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_getter(field) {
                map.insert(field.name().to_owned(), Input::Type(if is_field_output_omissible(field) {
                    field.type_expr.resolved().to_optional()
                } else {
                    field.type_expr.resolved().clone()
                }));
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            map.insert(field.name().to_owned(), Input::Type(if is_field_output_omissible(field) {
                field.type_expr.resolved().to_optional()
            } else {
                field.type_expr.resolved().clone()
            }));
        }
    }
    Input::Shape(Shape::new(map))
}

fn resolve_count_aggregate_result_type(model: &Model) -> Input {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Int64.to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Input::Type(Type::Int64.to_optional()));
            }
        }
    }
    map.insert("_all".to_owned(), Input::Type(Type::Int64.to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_sum_aggregate_result_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr.resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                if field.type_expr.resolved().is_int_32_or_64() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Int64.to_optional()));
                } else if field.type_expr.resolved().is_float_32_or_64() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Float.to_optional()));
                } else if field.type_expr.resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Decimal.to_optional()));
                }
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr.resolved().is_any_number() && settings.cached {
                if field.type_expr.resolved().is_int_32_or_64() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Int64.to_optional()));
                } else if field.type_expr.resolved().is_float_32_or_64() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Float.to_optional()));
                } else if field.type_expr.resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Decimal.to_optional()));
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

fn resolve_avg_aggregate_result_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr.resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                if field.type_expr.resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Decimal.to_optional()));
                } else {
                    map.insert(field.name().to_owned(), Input::Type(Type::Float.to_optional()));
                }
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr.resolved().is_any_number() && settings.cached {
                if field.type_expr.resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Input::Type(Type::Decimal.to_optional()));
                } else {
                    map.insert(field.name().to_owned(), Input::Type(Type::Float.to_optional()));
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

fn resolve_min_aggregate_result_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().to_optional()));
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_max_aggregate_result_type(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().to_optional()));
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_aggregate_result_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CountAggregateResult(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_sum_aggregate {
        map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::SumAggregateResult(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_avg_aggregate {
        map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::AvgAggregateResult(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_min_aggregate {
        map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::MinAggregateResult(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_max_aggregate {
        map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::MaxAggregateResult(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_group_by_result_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().to_optional()));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Input::Type(field.type_expr.resolved().to_optional()));
            }
        }
    }
    map.extend(resolve_aggregate_result_type(model, availability).into_shape().unwrap().into_iter());
    Input::Shape(Shape::new(map))
}

fn resolve_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_find_unique_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_find_first_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::OrderByInput(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    map.insert("cursor".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_scalar_field_enum {
        map.insert("distinct".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ScalarFieldEnum(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    map.insert("take".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("skip".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageSize".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageNumber".to_owned(), Input::Type(Type::Int64.to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_find_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    resolve_find_first_args_type(model, availability)
}

fn resolve_create_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CreateInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_update_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_upsert_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CreateInput(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_copy_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    map.insert("copy".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_delete_args_type(model: &Model) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone()))));
    Input::Shape(Shape::new(map))
}

fn resolve_create_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CreateInput(model.path.clone(), model.string_path.clone())).to_enumerable()));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_update_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_copy_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    map.insert("copy".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::UpdateInput(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Select(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_include {
        map.insert("include".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Include(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_delete_many_args_type(model: &Model) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone()))));
    Input::Shape(Shape::new(map))
}

fn resolve_count_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::OrderByInput(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_scalar_field_enum {
        map.insert("distinct".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ScalarFieldEnum(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    map.insert("cursor".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("take".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("skip".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageSize".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageNumber".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("select".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CountAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    Input::Shape(Shape::new(map))
}

fn resolve_aggregate_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::OrderByInput(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_scalar_field_enum {
        map.insert("distinct".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ScalarFieldEnum(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    map.insert("cursor".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("take".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("skip".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageSize".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageNumber".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CountAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_sum_aggregate {
        map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::SumAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_avg_aggregate {
        map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::AvgAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_min_aggregate {
        map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::MinAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_max_aggregate {
        map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::MaxAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
}

fn resolve_group_by_args_type(model: &Model, availability: &ShapeAvailableContext) -> Input {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereInput(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("by".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ScalarFieldEnum(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("having".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ScalarWhereWithAggregatesInput(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::OrderByInput(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    map.insert("distinct".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ScalarFieldEnum(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("cursor".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::WhereUniqueInput(model.path.clone(), model.string_path.clone())).to_optional()));
    map.insert("take".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("skip".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageSize".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("pageNumber".to_owned(), Input::Type(Type::Int64.to_optional()));
    map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::CountAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    if availability.has_sum_aggregate {
        map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::SumAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_avg_aggregate {
        map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::AvgAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_min_aggregate {
        map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::MinAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    if availability.has_max_aggregate {
        map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::MaxAggregateInputType(model.path.clone(), model.string_path.clone())).to_optional()));
    }
    Input::Shape(Shape::new(map))
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

fn is_field_atomic(field: &Field) -> bool {
    field_has_decorator_name(field, "atomic")
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
    let mut decorator_names = decorator.identifier_path.names();
    if *decorator_names.first().unwrap() == "std" {
        decorator_names.shift();
    }
    if decorator_names.len() != 1 {
        return false;
    }
    let name = *decorator_names.last().unwrap();
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

fn field_update_input_for_type<'a>(t: &Type, atomic: bool) -> Option<Input> {
    if atomic {
        if let Some(inner_type) = t.unwrap_optional().as_array() {
            if t.is_optional() {
                Some(Input::Type(Type::Union(vec![
                    Type::Array(Box::new(inner_type.clone())),
                    Type::Null,
                    Type::ShapeReference(ShapeReference::ArrayAtomicUpdateOperationInput(Box::new(t.unwrap_optional().clone()))),
                ]).to_optional()))
            } else {
                Some(Input::Type(Type::Union(vec![
                    Type::Array(Box::new(inner_type.clone())),
                    Type::ShapeReference(ShapeReference::ArrayAtomicUpdateOperationInput(Box::new(t.unwrap_optional().clone()))),
                ]).to_optional()))
            }
        } else {
            if let Some(input) = STATIC_UPDATE_INPUT_FOR_TYPE.get(t) {
                Some(input.clone())
            } else {
                if t.is_optional() {
                    Some(Input::Type(Type::Union(vec![
                        t.unwrap_optional().clone(),
                        Type::Null,
                    ])))
                } else {
                    Some(Input::Type(t.clone()))
                }
            }
        }
    } else {
        if t.is_optional() {
            Some(Input::Type(Type::Union(vec![
                t.unwrap_optional().clone(),
                Type::Null,
            ])))
        } else {
            Some(Input::Type(t.clone()))
        }
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

fn is_field_input_omissible(field: &Field) -> bool {
    field_has_decorator_name(field, "inputOmissible")
}

fn is_field_output_omissible(field: &Field) -> bool {
    field_has_decorator_name(field, "outputOmissible")
}

fn field_has_default(field: &Field) -> bool {
    field_has_decorator_name(field, "default")
}

fn field_has_on_save(field: &Field) -> bool {
    field_has_decorator_name(field, "onSave")
}

fn get_opposite_relation_field<'a>(field: &'a Field, context: &'a ResolverContext<'a>) -> Option<&'a Field> {
    let relation_decorator = field.decorators.iter().find(|d| d.identifier_path.identifiers.last().unwrap().name() == "relation")?;
    let argument_list = relation_decorator.argument_list.as_ref()?;
    let that_model_ref = field.type_expr.resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object()?;
    let that_model = context.schema.find_top_by_path(that_model_ref.0)?.as_model()?;

    let fields = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "fields");
    let references = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "references");
    let local = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "local");
    let foreign = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "foreign");
    let through = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "through");
    if fields.is_some() && references.is_some() {
        let fields = fields.unwrap();
        let references = references.unwrap();
        let fields_value = fields.value.unwrap_enumerable_enum_member_strings();
        let references_value = references.value.unwrap_enumerable_enum_member_strings();
        if fields_value.is_some() && references_value.is_some() {
            find_relation_field_in_model(that_model, references_value.unwrap(), fields_value.unwrap())
        } else {
            None
        }
    } else if local.is_some() && foreign.is_some() && through.is_some() {
        let local = local.unwrap();
        let foreign = foreign.unwrap();
        let through = through.unwrap();
        let through_path = unwrap_model_path_in_expression_kind(&through.value.kind, that_model, context)?;
        let local_value = local.value.unwrap_enumerable_enum_member_string();
        let foreign_value = foreign.value.unwrap_enumerable_enum_member_string();
        if local_value.is_some() && foreign_value.is_some() {
            find_indirect_relation_field_in_model(that_model, through_path, foreign_value.unwrap(), local_value.unwrap(), context)
        } else {
            None
        }
    } else {
        None
    }
}

fn find_relation_field_in_model<'a>(model: &'a Model, fields: Vec<&str>, references: Vec<&str>) -> Option<&'a Field> {
    for field in &model.fields {
        if field.resolved().class.is_model_relation() {
            let relation_decorator = field.decorators.iter().find(|d| d.identifier_path.identifiers.last().unwrap().name() == "relation")?;
            let argument_list = relation_decorator.argument_list.as_ref()?;
            let fields_arg = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "fields")?;
            let references_arg = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "references")?;
            let fields_ref = fields_arg.value.unwrap_enumerable_enum_member_strings()?;
            let references_ref = references_arg.value.unwrap_enumerable_enum_member_strings()?;
            if fields_ref == fields && references_ref == references {
                return Some(field);
            }
        }
    }
    None
}

fn find_indirect_relation_field_in_model<'a>(model: &'a Model, through_path: Vec<usize>, local: &str, foreign: &str, context: &'a ResolverContext<'a>) -> Option<&'a Field> {
    for field in &model.fields {
        if field.resolved().class.is_model_relation() {
            let relation_decorator = field.decorators.iter().find(|d| d.identifier_path.identifiers.last().unwrap().name() == "relation")?;
            let argument_list = relation_decorator.argument_list.as_ref()?;
            let through = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "through")?;
            let local_arg = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "local")?;
            let foreign_arg = argument_list.arguments.iter().find(|a| a.name.is_some() && a.name.as_ref().unwrap().name() == "foreign")?;
            let local_value = local_arg.value.unwrap_enumerable_enum_member_string()?;
            let foreign_value = foreign_arg.value.unwrap_enumerable_enum_member_string()?;
            if let Some(path) = unwrap_model_path_in_expression_kind(&through.value.kind, model, context) {
                if path == through_path && local_value == local && foreign_value == foreign {
                    return Some(field);
                }
            }
        }
    }
    None
}

fn unwrap_model_path_in_expression_kind<'a>(kind: &'a ExpressionKind, model: &'a Model, context: &'a ResolverContext<'a>) -> Option<Vec<usize>> {
    match kind {
        ExpressionKind::ArithExpr(a) => unwrap_model_path_in_arith_expr(a, model, context),
        ExpressionKind::Unit(u) => unwrap_model_path_in_unit(u, model, context),
        ExpressionKind::Identifier(i) => unwrap_model_path_in_identifier(i, model, context),
        _ => None,
    }
}

fn unwrap_model_path_in_arith_expr<'a>(arith_expr: &'a ArithExpr, model: &'a Model, context: &'a ResolverContext<'a>) -> Option<Vec<usize>> {
    match arith_expr {
        ArithExpr::Expression(e) => unwrap_model_path_in_expression_kind(&e.kind, model, context),
        _ => None,
    }
}

fn unwrap_model_path_in_identifier<'a>(identifier: &'a Identifier, model: &'a Model, context: &'a ResolverContext<'a>) -> Option<Vec<usize>> {
    resolve_identifier(identifier, context, ReferenceType::Default, model.availability())
}

fn unwrap_model_path_in_unit<'a>(unit: &'a Unit, model: &'a Model, context: &'a ResolverContext<'a>) -> Option<Vec<usize>> {
    let resolved = resolve_unit(unit, context, &Type::Undetermined, &btreemap! {});
    if let Some(value) = &resolved.value {
        let path: Vec<&str> = value.as_array()?.iter().map(|i| i.as_str()).collect::<Option<Vec<_>>>()?;
        return search_identifier_path_in_source(context.schema, context.source(), &if context.current_namespace().is_some() {
            context.current_namespace().unwrap().str_path()
        } else {
            vec![]
        }, &path, &top_filter_for_reference_type(ReferenceType::Default), model.availability());
    }
    None
}

struct ShapeAvailableContext {
    has_select: bool,
    has_include: bool,
    has_where: bool,
    has_where_unique: bool,
    has_where_with_aggregates: bool,
    has_order_by: bool,
    has_scalar_field_enum: bool,
    has_sum_aggregate: bool,
    has_avg_aggregate: bool,
    has_min_aggregate: bool,
    has_max_aggregate: bool,
}

impl ShapeAvailableContext {
    
    fn new() -> Self {
        Self {
            has_select: false,
            has_include: false,
            has_where: false,
            has_where_unique: false,
            has_where_with_aggregates: false,
            has_order_by: false,
            has_scalar_field_enum: false,
            has_sum_aggregate: false,
            has_avg_aggregate: false,
            has_min_aggregate: false,
            has_max_aggregate: false,
        }
    }

    fn has_args(&self) -> bool {
        self.has_select && self.has_include
    }

    fn has_group_by(&self) -> bool {
        self.has_scalar_field_enum
    }
}