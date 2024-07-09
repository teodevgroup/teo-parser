use array_tool::vec::Shift;
use indexmap::{indexmap, IndexMap};
use maplit::btreemap;
use crate::ast::arith_expr::ArithExpr;
use crate::availability::Availability;
use crate::ast::decorator::Decorator;
use crate::ast::expression::ExpressionKind;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::model::{Model};
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::synthesized_shape_declaration::SynthesizedShapeDeclaration;
use crate::ast::unit::Unit;
use crate::expr::ReferenceType;
use crate::r#type::keyword::Keyword;
use crate::r#type::reference::Reference;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::synthesized_enum::{SynthesizedEnum, SynthesizedEnumMember};
use crate::r#type::synthesized_enum_reference::{SynthesizedEnumReference, SynthesizedEnumReferenceKind};
use crate::r#type::synthesized_interface_enum::{SynthesizedInterfaceEnum, SynthesizedInterfaceEnumMember};
use crate::r#type::synthesized_interface_enum_reference::SynthesizedInterfaceEnumReferenceKind;
use crate::r#type::Type;
use crate::r#type::synthesized_shape_reference::{SynthesizedShapeReference, SynthesizedShapeReferenceKind};
use crate::resolver::resolve_identifier::resolve_identifier;
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::has_availability::HasAvailability;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_model_shapes<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    if !context.current_availability().contains(Availability::database()) {
        return
    }
    let mut enums = IndexMap::new();
    let mut interface_enums = IndexMap::new();
    let mut shapes = IndexMap::new();
    let mut shape_available_context = ShapeAvailableContext::new();

    // scalar field
    enums.insert(SynthesizedEnumReferenceKind::ScalarFields, resolve_model_scalar_fields(model));

    // serializable scalar field
    enums.insert(SynthesizedEnumReferenceKind::SerializableScalarFields, resolve_model_serializable_scalar_fields(model));
    shape_available_context.has_serializable_scalar_fields = true;

    // relations
    enums.insert(SynthesizedEnumReferenceKind::Relations, resolve_model_relations(model));

    // direct relations
    enums.insert(SynthesizedEnumReferenceKind::DirectRelations, resolve_model_direct_relations(model));

    // indirect relations
    enums.insert(SynthesizedEnumReferenceKind::IndirectRelations, resolve_model_indirect_relations(model));

    // field indexes
    interface_enums.insert(SynthesizedInterfaceEnumReferenceKind::FieldIndexes, resolve_model_field_indexes(model, context));

    // select
    shapes.insert((SynthesizedShapeReferenceKind::Select, None), resolve_model_select_shape(model));
    shape_available_context.has_select = true;

    // include
    shapes.insert((SynthesizedShapeReferenceKind::Include, None), resolve_model_include_shape(model));
    shape_available_context.has_include = true;

    // where input
    shapes.insert((SynthesizedShapeReferenceKind::WhereInput, None), resolve_model_where_input_shape(model, true, false, context));
    shape_available_context.has_where = true;

    // where unique input
    shapes.insert((SynthesizedShapeReferenceKind::WhereUniqueInput, None), resolve_model_where_unique_input_shape(model));
    shape_available_context.has_where_unique = true;

    // scalar where with aggregates input
    shapes.insert((SynthesizedShapeReferenceKind::ScalarWhereWithAggregatesInput, None), resolve_model_where_input_shape(model, false, true, context));
    shape_available_context.has_where_with_aggregates = true;


    // relation filter
    shapes.insert((SynthesizedShapeReferenceKind::RelationFilter, None), resolve_model_relation_filter(model));
    // list relation filter
    shapes.insert((SynthesizedShapeReferenceKind::ListRelationFilter, None), resolve_model_list_relation_filter(model));

    // order by input
    shapes.insert((SynthesizedShapeReferenceKind::OrderByInput, None), resolve_model_order_by_input_shape(model, context));
    shape_available_context.has_order_by = true;

    // count aggregate input type
    shapes.insert((SynthesizedShapeReferenceKind::CountAggregateInputType, None), resolve_count_aggregate_input_type(model));

    // sum aggregate input type
    shapes.insert((SynthesizedShapeReferenceKind::SumAggregateInputType, None), resolve_sum_aggregate_input_type(model));
    shape_available_context.has_sum_aggregate = true;

    // avg aggregate input type
    shapes.insert((SynthesizedShapeReferenceKind::AvgAggregateInputType, None), resolve_avg_aggregate_input_type(model));
    shape_available_context.has_avg_aggregate = true;

    // min aggregate input type
    shapes.insert((SynthesizedShapeReferenceKind::MinAggregateInputType, None), resolve_min_aggregate_input_type(model));
    shape_available_context.has_min_aggregate = true;

    // max aggregate input type
    shapes.insert((SynthesizedShapeReferenceKind::MaxAggregateInputType, None), resolve_max_aggregate_input_type(model));
    shape_available_context.has_max_aggregate = true;

    // create input
    shapes.insert((SynthesizedShapeReferenceKind::CreateInput, None), resolve_create_input_type(model, None, context));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::CreateInputWithout, Some(field.name().to_owned())), resolve_create_input_type(model, Some(field.name()), context));
        }
    }
    // update input
    shapes.insert((SynthesizedShapeReferenceKind::UpdateInput, None), resolve_update_input_type(model, None, context));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::UpdateInputWithout, Some(field.name().to_owned())), resolve_update_input_type(model, Some(field.name()), context));
        }
    }
    // create nested one input
    shapes.insert((SynthesizedShapeReferenceKind::CreateNestedOneInput, None), resolve_create_nested_one_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::CreateNestedOneInputWithout, Some(field.name().to_owned())), resolve_create_nested_one_input_type(model, Some(field.name())));
        }
    }
    // create nested many input
    shapes.insert((SynthesizedShapeReferenceKind::CreateNestedManyInput, None), resolve_create_nested_many_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::CreateNestedManyInputWithout, Some(field.name().to_owned())), resolve_create_nested_many_input_type(model, Some(field.name())));
        }
    }
    // update nested one input
    shapes.insert((SynthesizedShapeReferenceKind::UpdateNestedOneInput, None), resolve_update_nested_one_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::UpdateNestedOneInputWithout, Some(field.name().to_owned())), resolve_update_nested_one_input_type(model, Some(field.name())));
        }
    }
    // update nested many input
    shapes.insert((SynthesizedShapeReferenceKind::UpdateNestedManyInput, None), resolve_update_nested_many_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::UpdateNestedManyInputWithout, Some(field.name().to_owned())), resolve_update_nested_many_input_type(model, Some(field.name())));
        }
    }
    // connect or create input
    shapes.insert((SynthesizedShapeReferenceKind::ConnectOrCreateInput, None), resolve_connect_or_create_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::ConnectOrCreateInputWithout, Some(field.name().to_owned())), resolve_connect_or_create_input_type(model, Some(field.name())));
        }
    }
    // update with where unique input
    shapes.insert((SynthesizedShapeReferenceKind::UpdateWithWhereUniqueInput, None), resolve_update_with_where_unique_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::UpdateWithWhereUniqueInputWithout, Some(field.name().to_owned())), resolve_update_with_where_unique_input_type(model, Some(field.name())));
        }
    }
    // upsert with where unique input
    shapes.insert((SynthesizedShapeReferenceKind::UpsertWithWhereUniqueInput, None), resolve_upsert_with_where_unique_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::UpsertWithWhereUniqueInputWithout, Some(field.name().to_owned())), resolve_upsert_with_where_unique_input_type(model, Some(field.name())));
        }
    }
    // update many with where input
    shapes.insert((SynthesizedShapeReferenceKind::UpdateManyWithWhereInput, None), resolve_update_many_with_where_input_type(model, None));
    for field in model.fields() {
        if field.resolved().class.as_model_relation().is_some() {
            shapes.insert((SynthesizedShapeReferenceKind::UpdateManyWithWhereInputWithout, Some(field.name().to_owned())), resolve_update_many_with_where_input_type(model, Some(field.name())));
        }
    }
    // result
    shapes.insert((SynthesizedShapeReferenceKind::Result, None), resolve_result_type(model));
    // count aggregate result
    shapes.insert((SynthesizedShapeReferenceKind::CountAggregateResult, None), resolve_count_aggregate_result_type(model));
    // sum aggregate result
    shapes.insert((SynthesizedShapeReferenceKind::SumAggregateResult, None), resolve_sum_aggregate_result_type(model));
    // avg aggregate result
    shapes.insert((SynthesizedShapeReferenceKind::AvgAggregateResult, None), resolve_avg_aggregate_result_type(model));
    // min aggregate result
    shapes.insert((SynthesizedShapeReferenceKind::MinAggregateResult, None), resolve_min_aggregate_result_type(model));
    // max aggregate result
    shapes.insert((SynthesizedShapeReferenceKind::MaxAggregateResult, None), resolve_max_aggregate_result_type(model));
    // aggregate result
    shapes.insert((SynthesizedShapeReferenceKind::AggregateResult, None), resolve_aggregate_result_type(model, &shape_available_context));
    // group by result
    shapes.insert((SynthesizedShapeReferenceKind::GroupByResult, None), resolve_group_by_result_type(model, &shape_available_context));
    // args
    shapes.insert((SynthesizedShapeReferenceKind::Args, None), resolve_args_type(model, &shape_available_context));
    // find many args
    shapes.insert((SynthesizedShapeReferenceKind::FindManyArgs, None), resolve_find_many_args_type(model, &shape_available_context));
    // find first args
    shapes.insert((SynthesizedShapeReferenceKind::FindFirstArgs, None), resolve_find_first_args_type(model, &shape_available_context));
    // find unique args
    shapes.insert((SynthesizedShapeReferenceKind::FindUniqueArgs, None), resolve_find_unique_args_type(model, &shape_available_context));
    // create args
    shapes.insert((SynthesizedShapeReferenceKind::CreateArgs, None), resolve_create_args_type(model, &shape_available_context));
    // update args
    shapes.insert((SynthesizedShapeReferenceKind::UpdateArgs, None), resolve_update_args_type(model, &shape_available_context));
    // upsert args
    shapes.insert((SynthesizedShapeReferenceKind::UpsertArgs, None), resolve_upsert_args_type(model, &shape_available_context));
    // copy args
    shapes.insert((SynthesizedShapeReferenceKind::CopyArgs, None), resolve_copy_args_type(model, &shape_available_context));
    // delete args
    shapes.insert((SynthesizedShapeReferenceKind::DeleteArgs, None), resolve_delete_args_type(model, &shape_available_context));
    // create many args
    shapes.insert((SynthesizedShapeReferenceKind::CreateManyArgs, None), resolve_create_many_args_type(model, &shape_available_context));
    // update many args
    shapes.insert((SynthesizedShapeReferenceKind::UpdateManyArgs, None), resolve_update_many_args_type(model, &shape_available_context));
    // delete many args
    shapes.insert((SynthesizedShapeReferenceKind::DeleteManyArgs, None), resolve_delete_many_args_type(model, &shape_available_context));
    // copy many args
    shapes.insert((SynthesizedShapeReferenceKind::CopyManyArgs, None), resolve_copy_many_args_type(model, &shape_available_context));
    // count args
    shapes.insert((SynthesizedShapeReferenceKind::CountArgs, None), resolve_count_args_type(model, &shape_available_context));
    // aggregate args
    shapes.insert((SynthesizedShapeReferenceKind::AggregateArgs, None), resolve_aggregate_args_type(model, &shape_available_context));
    // group by args
    shapes.insert((SynthesizedShapeReferenceKind::GroupByArgs, None), resolve_group_by_args_type(model, &shape_available_context));

    // scalar update input
    shapes.insert((SynthesizedShapeReferenceKind::ScalarUpdateInput, None), resolve_scalar_update_input(model));

    model.resolved_mut().enums = enums;
    model.resolved_mut().shapes = shapes;
    model.resolved_mut().interface_enums = interface_enums;
}

fn resolve_model_select_shape(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(field_settings) = field.resolved().class.as_model_primitive_field() {
            if !field_settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_getter(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_model_include_shape(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(_) = field.resolved().class.as_model_relation() {
            if let Some(related_reference) = field.type_expr().resolved().unwrap_optional().unwrap_array().as_model_object() {
                if relation_is_many(field) {
                    // many
                    map.insert(
                        field.name().to_owned(),
                        Type::Union(vec![
                            Type::SynthesizedShapeReference(SynthesizedShapeReference::find_many_args(related_reference.clone())),
                            Type::Bool,
                        ]).wrap_in_optional()
                    );
                } else {
                    // single
                    map.insert(
                        field.name().to_owned(),
                        Type::Union(vec![
                            Type::SynthesizedShapeReference(SynthesizedShapeReference::args(related_reference.clone())),
                            Type::Bool,
                        ]).wrap_in_optional()
                    );
                }
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_model_where_input_shape<'a>(model: &Model, include_relations: bool, with_aggregates: bool, context: &'a ResolverContext<'a>) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && is_field_queryable(field) && !is_field_writeonly(field) {
                if with_aggregates {
                    map.insert(field.name().to_owned(), resolve_static_where_with_aggregates_input_for_type(field.type_expr().resolved(), context));
                } else {
                    map.insert(field.name().to_owned(), resolve_static_where_input_for_type(field.type_expr().resolved(), context).clone());

                }
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached && is_field_queryable(field) {
                if with_aggregates {
                    map.insert(field.name().to_owned(), resolve_static_where_with_aggregates_input_for_type(field.type_expr().resolved(), context));
                } else {
                    map.insert(field.name().to_owned(), resolve_static_where_with_aggregates_input_for_type(field.type_expr().resolved(), context));
                }
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            if include_relations {
                if let Some(related_reference) = field.type_expr().resolved().unwrap_optional().unwrap_array().as_model_object() {
                    if relation_is_many(field) {
                        // many
                        map.insert(
                            field.name().to_owned(),
                            Type::SynthesizedShapeReference(SynthesizedShapeReference::list_relation_filter(related_reference.clone())).wrap_in_optional()
                        );
                    } else {
                        // single
                        map.insert(
                            field.name().to_owned(),
                            Type::SynthesizedShapeReference(SynthesizedShapeReference::relation_filter(related_reference.clone())).wrap_in_optional()
                        );
                    }
                }
            }
        }
    }
    // insert the three ops
    map.insert("AND".to_owned(), Type::SynthesizedShapeReference(
        SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))
    ).wrap_in_array().wrap_in_optional());
    map.insert("OR".to_owned(), Type::SynthesizedShapeReference(
        SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))
    ).wrap_in_array().wrap_in_optional());
    map.insert("NOT".to_owned(), Type::SynthesizedShapeReference(
        SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))
    ).wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_model_where_unique_input_shape(model: &Model) -> Type {
    let mut inputs = vec![];
    for decorator in model.decorators() {
        if decorator_has_any_name(decorator, vec!["id", "unique"]) {
            if let Some(argument_list) = decorator.argument_list() {
                if let Some(argument) = argument_list.arguments().next() {
                    if let Some(array_literal) = argument.value().kind.as_array_literal() {
                        let mut map = indexmap! {};
                        for expression in array_literal.expressions() {
                            if let Some(enum_variant_literal) = expression.kind.as_enum_variant_literal() {
                                let name = enum_variant_literal.identifier().name();
                                if let Some(field) = model.fields().find(|f| f.identifier().name() == name) {
                                    map.insert(field.name().to_owned(), field.type_expr().resolved().clone());
                                }
                            }
                        }
                        if !map.is_empty() {
                            inputs.push(Type::SynthesizedShape(SynthesizedShape::new(map)));
                        }
                    }
                }
            }
        }
    }
    for field in model.fields() {
        for decorator in field.decorators() {
            if decorator_has_any_name(decorator, vec!["id", "unique"]) {
                inputs.push(Type::SynthesizedShape(SynthesizedShape::new(indexmap! {
                    field.name().to_owned() => field.type_expr().resolved().clone()
                })));
            }
        }
    }
    Type::Union(inputs)
}

fn resolve_model_relation_filter(model: &Model) -> Type {
    let mut map = indexmap! {};
    map.insert("is".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("isNot".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_model_list_relation_filter(model: &Model) -> Type {
    let mut map = indexmap! {};
    map.insert("every".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("some".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("none".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_model_order_by_input_shape<'a>(model: &'a Model, context: &'a ResolverContext<'a>) -> Type {
    let sort = context.schema.std_source().find_node_by_string_path(&vec!["std", "Sort"], &top_filter_for_reference_type(ReferenceSpace::Default), Availability::default()).unwrap().as_enum().unwrap();
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && is_field_sortable(field) && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::EnumVariant(Reference::new(sort.path.clone(), sort.string_path.clone())).wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached && is_field_sortable(field) {
                map.insert(field.name().to_owned(), Type::EnumVariant(Reference::new(sort.path.clone(), sort.string_path.clone())).wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_model_scalar_fields(model: &Model) -> SynthesizedEnum {
    let mut members = vec![];
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment().cloned(),
                });
            }
        }
    }
    SynthesizedEnum::new(members)
}

fn resolve_model_relations(model: &Model) -> SynthesizedEnum {
    let mut members = vec![];
    for field in model.fields() {
        if let Some(_) = field.resolved().class.as_model_relation() {
            members.push(SynthesizedEnumMember {
                name: field.name().to_owned(),
                comment: field.comment().cloned(),
            });
        }
    }
    SynthesizedEnum::new(members)
}

fn resolve_model_direct_relations(model: &Model) -> SynthesizedEnum {
    let mut members = vec![];
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_relation() {
            if settings.direct {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment().cloned(),
                });
            }
        }
    }
    SynthesizedEnum::new(members)
}

fn resolve_model_indirect_relations(model: &Model) -> SynthesizedEnum {
    let mut members = vec![];
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_relation() {
            if !settings.direct {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment().cloned(),
                });
            }
        }
    }
    SynthesizedEnum::new(members)
}

fn resolve_model_field_indexes(model: &Model, context: &ResolverContext) -> SynthesizedInterfaceEnum {
    let mut members = vec![];
    let sort = context.schema.std_source().find_node_by_string_path(&vec!["std", "Sort"], &top_filter_for_reference_type(ReferenceSpace::Default), Availability::default()).unwrap().as_enum().unwrap();
    let sort_type = Type::EnumVariant(Reference::new(sort.path.clone(), sort.string_path.clone()));
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) && !is_field_virtual(field) {
                members.push(SynthesizedInterfaceEnumMember::new(
                    field.name().to_owned(),
                    field.comment().cloned(),
                    indexmap! {
                        "sort".to_owned() => sort_type.wrap_in_optional(),
                        "length".to_owned() => Type::Int.wrap_in_optional(),
                    }
                ));
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                members.push(SynthesizedInterfaceEnumMember::new(
                    field.name().to_owned(),
                    field.comment().cloned(),
                    indexmap! {
                        "sort".to_owned() => sort_type.wrap_in_optional(),
                        "length".to_owned() => Type::Int.wrap_in_optional(),
                    }
                ));
            }
        }
    }
    SynthesizedInterfaceEnum::new(members)
}

fn resolve_model_serializable_scalar_fields(model: &Model) -> SynthesizedEnum {
    let mut members = vec![];
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) && !is_field_virtual(field) {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment().cloned(),
                });
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                members.push(SynthesizedEnumMember {
                    name: field.name().to_owned(),
                    comment: field.comment().cloned(),
                });
            }
        }
    }
    SynthesizedEnum::new(members)
}

fn resolve_count_aggregate_input_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        }
    }
    map.insert("_all".to_owned(), Type::Bool.wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_sum_aggregate_input_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr().resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr().resolved().is_any_number() && settings.cached {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_avg_aggregate_input_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr().resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr().resolved().is_any_number() && settings.cached {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_min_aggregate_input_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_max_aggregate_input_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Type::Bool.wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_create_input_type<'a>(model: &'a Model, without: Option<&str>, context: &'a ResolverContext<'a>) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_readonly(field) {
                let optional = is_field_input_omissible(field) || field_has_on_save(field) || field_has_default(field) || field_is_foreign_key(field);
                let mut t = field.type_expr().resolved().clone();
                if optional {
                    t = t.wrap_in_optional();
                }
                map.insert(field.name().to_owned(), t);
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_setter(field) {
                let optional = is_field_input_omissible(field);
                let mut t = field.type_expr().resolved().clone();
                if optional {
                    t = t.wrap_in_optional();
                }
                map.insert(field.name().to_owned(), t);
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            if let Some(without) = without {
                if field.name() == without {
                    continue
                }
            }
            if let Some(that_model) = field.type_expr().resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object() {
                if relation_is_many(field) {
                    if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::create_nested_many_input_without(that_model.clone(), opposite_relation_field.name().to_owned())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    } else {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::create_nested_many_input(that_model.clone())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    }
                } else {
                    if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::create_nested_one_input_without(that_model.clone(), opposite_relation_field.name().to_owned())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    } else {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::create_nested_one_input(that_model.clone())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    }
                }
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_scalar_update_input(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_input_type<'a>(model: &'a Model, without: Option<&str>, context: &'a ResolverContext<'a>) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_readonly(field) {
                map.insert(field.name().to_owned(), resolve_static_update_input_for_type(field.type_expr().resolved(), is_field_atomic(field), context).wrap_in_optional());
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_setter(field) {
                map.insert(field.name().to_owned(), resolve_static_update_input_for_type(field.type_expr().resolved(), false, context).wrap_in_optional());
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            if let Some(without) = without {
                if field.name() == without {
                    continue
                }
            }
            if let Some(that_model) = field.type_expr().resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object() {
                if relation_is_many(field) {
                    if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::update_nested_many_input_without(that_model.clone(), opposite_relation_field.name().to_owned())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    } else {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::update_nested_many_input(that_model.clone())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    }
                } else {
                    if let Some(opposite_relation_field) = get_opposite_relation_field(field, context) {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::update_nested_one_input_without(that_model.clone(), opposite_relation_field.name().to_owned())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    } else {
                        let t = Type::SynthesizedShapeReference(SynthesizedShapeReference::update_nested_one_input(that_model.clone())).wrap_in_optional();
                        map.insert(field.name().to_owned(), t);
                    }
                }
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_create_nested_one_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_optional());
    map.insert("connectOrCreate".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::connect_or_create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::connect_or_create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_optional());
    map.insert("connect".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_create_nested_many_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("connectOrCreate".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::connect_or_create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::connect_or_create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("connect".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_nested_one_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_optional());
    map.insert("connectOrCreate".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::connect_or_create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::connect_or_create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_optional());
    map.insert("connect".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("set".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::update_with_where_unique_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::update_with_where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_optional());
    map.insert("upsert".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::upsert_with_where_unique_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::upsert_with_where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_optional());
    map.insert("disconnect".to_owned(), Type::Bool.wrap_in_optional());
    map.insert("delete".to_owned(), Type::Bool.wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_nested_many_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("connectOrCreate".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::connect_or_create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::connect_or_create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("connect".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    map.insert("set".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::update_with_where_unique_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::update_with_where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("upsert".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::upsert_with_where_unique_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::upsert_with_where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("disconnect".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    map.insert("delete".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    map.insert("updateMany".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::update_many_with_where_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::update_many_with_where_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }).wrap_in_enumerable().wrap_in_optional());
    map.insert("deleteMany".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_connect_or_create_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }));
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_with_where_unique_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::update_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }));
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_upsert_with_where_unique_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::create_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }));
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::update_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }));
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_many_with_where_input_type(model: &Model, without: Option<&str>) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(if let Some(without) = without {
        SynthesizedShapeReference::update_input_without(Reference::new(model.path.clone(), model.string_path.clone()), without.to_owned())
    } else {
        SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))
    }));
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_result_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), if is_field_output_omissible(field) {
                    field.type_expr().resolved().wrap_in_optional()
                } else {
                    field.type_expr().resolved().clone()
                });
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_getter(field) {
                map.insert(field.name().to_owned(), if is_field_output_omissible(field) {
                    field.type_expr().resolved().wrap_in_optional()
                } else {
                    field.type_expr().resolved().clone()
                });
            }
        } else if let Some(_) = field.resolved().class.as_model_relation() {
            let optional = field.type_expr().resolved().is_optional();
            let vec = field.type_expr().resolved().unwrap_optional().is_array();
            if let Some(reference) = field.type_expr().resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object() {
                let mut return_type = Type::SynthesizedShapeReference(SynthesizedShapeReference::result(reference.clone()));
                if vec {
                    return_type = Type::Array(Box::new(return_type));
                }
                if optional {
                    return_type = return_type.wrap_in_optional();
                }
                map.insert(field.name().to_owned(), return_type);
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_count_aggregate_result_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Type::Int64.wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), Type::Int64.wrap_in_optional());
            }
        }
    }
    map.insert("_all".to_owned(), Type::Int64.wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_sum_aggregate_result_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr().resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                if field.type_expr().resolved().is_int_32_or_64() {
                    map.insert(field.name().to_owned(), Type::Int64.wrap_in_optional());
                } else if field.type_expr().resolved().is_float_32_or_64() {
                    map.insert(field.name().to_owned(), Type::Float.wrap_in_optional());
                } else if field.type_expr().resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Type::Decimal.wrap_in_optional());
                }
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr().resolved().is_any_number() && settings.cached {
                if field.type_expr().resolved().is_int_32_or_64() {
                    map.insert(field.name().to_owned(), Type::Int64.wrap_in_optional());
                } else if field.type_expr().resolved().is_float_32_or_64() {
                    map.insert(field.name().to_owned(), Type::Float.wrap_in_optional());
                } else if field.type_expr().resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Type::Decimal.wrap_in_optional());
                }
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_avg_aggregate_result_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if field.type_expr().resolved().is_any_number() && !settings.dropped && !is_field_writeonly(field) {
                if field.type_expr().resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Type::Decimal.wrap_in_optional());
                } else {
                    map.insert(field.name().to_owned(), Type::Float.wrap_in_optional());
                }
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if field.type_expr().resolved().is_any_number() && settings.cached {
                if field.type_expr().resolved().is_decimal() {
                    map.insert(field.name().to_owned(), Type::Decimal.wrap_in_optional());
                } else {
                    map.insert(field.name().to_owned(), Type::Float.wrap_in_optional());
                }
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_min_aggregate_result_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_max_aggregate_result_type(model: &Model) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_aggregate_result_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::count_aggregate_result(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_sum_aggregate {
        map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::sum_aggregate_result(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_avg_aggregate {
        map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::avg_aggregate_result(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_min_aggregate {
        map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::min_aggregate_result(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_max_aggregate {
        map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::max_aggregate_result(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_group_by_result_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    for field in model.fields() {
        if let Some(settings) = field.resolved().class.as_model_primitive_field() {
            if !settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        } else if let Some(settings) = field.resolved().class.as_model_property() {
            if settings.cached {
                map.insert(field.name().to_owned(), field.type_expr().resolved().wrap_in_optional());
            }
        }
    }
    map.extend(resolve_aggregate_result_type(model, availability).into_synthesized_shape().unwrap().into_iter());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_find_unique_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_find_first_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::order_by_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    }
    map.insert("cursor".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_serializable_scalar_fields {
        map.insert("distinct".to_owned(), Type::SynthesizedEnumReference(SynthesizedEnumReference::model_serializable_scalar_fields(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    map.insert("take".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("skip".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageSize".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageNumber".to_owned(), Type::Int64.wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_find_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    resolve_find_first_args_type(model, availability)
}

fn resolve_create_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_upsert_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_copy_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("copy".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_delete_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_create_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("create".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::create_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable());
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_update_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("update".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_copy_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    map.insert("copy".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::update_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_delete_many_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))));
    if availability.has_select {
        map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::select(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_include {
        map.insert("include".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::include(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_count_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::order_by_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    }
    if availability.has_serializable_scalar_fields {
        map.insert("distinct".to_owned(), Type::SynthesizedEnumReference(SynthesizedEnumReference::model_serializable_scalar_fields(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    map.insert("cursor".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("take".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("skip".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageSize".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageNumber".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("select".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::count_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_aggregate_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::order_by_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    }
    if availability.has_serializable_scalar_fields {
        map.insert("distinct".to_owned(), Type::SynthesizedEnumReference(SynthesizedEnumReference::model_serializable_scalar_fields(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    map.insert("cursor".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("take".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("skip".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageSize".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageNumber".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::count_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_sum_aggregate {
        map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::sum_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_avg_aggregate {
        map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::avg_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_min_aggregate {
        map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::min_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_max_aggregate {
        map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::max_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

fn resolve_group_by_args_type(model: &Model, availability: &ShapeAvailableContext) -> Type {
    let mut map = indexmap! {};
    map.insert("where".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("by".to_owned(), Type::SynthesizedEnumReference(SynthesizedEnumReference::model_serializable_scalar_fields(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable());
    map.insert("having".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::scalar_where_with_aggregates_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_order_by {
        map.insert("orderBy".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::order_by_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_enumerable().wrap_in_optional());
    }
    map.insert("distinct".to_owned(), Type::SynthesizedEnumReference(SynthesizedEnumReference::model_serializable_scalar_fields(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("cursor".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::where_unique_input(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    map.insert("take".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("skip".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageSize".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("pageNumber".to_owned(), Type::Int64.wrap_in_optional());
    map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::count_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    if availability.has_sum_aggregate {
        map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::sum_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_avg_aggregate {
        map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::avg_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_min_aggregate {
        map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::min_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    if availability.has_max_aggregate {
        map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::max_aggregate_input_type(Reference::new(model.path.clone(), model.string_path.clone()))).wrap_in_optional());
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

pub(super) fn relation_is_many(field: &Field) -> bool {
    field.type_expr().resolved().unwrap_optional().is_array()
}

pub(super) fn has_property_setter(field: &Field) -> bool {
    field_has_decorator_name(field, "setter")
}

pub(super) fn has_property_getter(field: &Field) -> bool {
    field_has_decorator_name(field, "getter")
}

pub(super) fn is_field_virtual(field: &Field) -> bool {
    field_has_decorator_name(field, "virtual")
}

pub(super) fn is_field_writeonly(field: &Field) -> bool {
    field_has_decorator_name(field, "writeonly")
}

pub(super) fn is_field_readonly(field: &Field) -> bool {
    field_has_decorator_name(field, "readonly")
}

pub(super) fn is_field_atomic(field: &Field) -> bool {
    field_has_decorator_name(field, "atomic")
}

pub(super) fn is_field_queryable(field: &Field) -> bool {
    !field_has_decorator_name(field, "unqueryable")
}

pub(super) fn is_field_sortable(field: &Field) -> bool {
    !field_has_decorator_name(field, "unsortable")
}

pub(super) fn field_has_decorator_name(field: &Field, name: &str) -> bool {
    field_has_decorator(field, |names| names == vec![name])
}

pub(super) fn field_has_decorator_names(field: &Field, names: Vec<&str>) -> bool {
    field_has_decorator(field, |ns| ns == names)
}

pub(super) fn field_has_decorator<F>(field: &Field, f: F) -> bool where F: Fn(Vec<&str>) -> bool {
    for decorator in field.decorators() {
        let names = if *decorator.identifier_path().names().first().unwrap() == "std" {
            let mut result = decorator.identifier_path().names();
            result.shift();
            result
        } else {
            decorator.identifier_path().names()
        };
        if f(names) {
            return true
        }
    }
    false
}

fn decorator_has_any_name(decorator: &Decorator, names: Vec<&str>) -> bool {
    let mut decorator_names = decorator.identifier_path().names();
    if *decorator_names.first().unwrap() == "std" {
        decorator_names.shift();
    }
    if decorator_names.len() != 1 {
        return false;
    }
    let name = *decorator_names.last().unwrap();
    names.contains(&name)
}

pub(super) fn is_field_input_omissible(field: &Field) -> bool {
    field_has_decorator_name(field, "inputOmissible")
}

pub(super) fn is_field_output_omissible(field: &Field) -> bool {
    field_has_decorator_name(field, "outputOmissible")
}

pub(super) fn field_has_default(field: &Field) -> bool {
    field_has_decorator_name(field, "default")
}

pub(super) fn field_is_foreign_key(field: &Field) -> bool {
    field_has_decorator_name(field, "foreignKey")
}

pub(super) fn field_has_on_save(field: &Field) -> bool {
    field_has_decorator_name(field, "onSave")
}

pub(super) fn get_opposite_relation_field<'a>(field: &'a Field, context: &'a ResolverContext<'a>) -> Option<&'a Field> {
    let relation_decorator = field.decorators().find(|d| *d.identifier_path().names().last().unwrap() == "relation")?;
    let argument_list = relation_decorator.argument_list()?;
    let that_model_ref = field.type_expr().resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object()?;
    let that_model = context.schema.find_top_by_path(that_model_ref.path())?.as_model()?;

    let fields = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "fields");
    let references = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "references");
    let local = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "local");
    let foreign = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "foreign");
    let through = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "through");
    if fields.is_some() && references.is_some() {
        let fields = fields.unwrap();
        let references = references.unwrap();
        let fields_value = fields.value().unwrap_enumerable_enum_member_strings();
        let references_value = references.value().unwrap_enumerable_enum_member_strings();
        if fields_value.is_some() && references_value.is_some() {
            find_relation_field_in_model(that_model, references_value.unwrap(), fields_value.unwrap())
        } else {
            None
        }
    } else if local.is_some() && foreign.is_some() && through.is_some() {
        let local = local.unwrap();
        let foreign = foreign.unwrap();
        let through = through.unwrap();
        let through_path = unwrap_model_path_in_expression_kind(&through.value().kind, that_model, context)?;
        let local_value = local.value().unwrap_enumerable_enum_member_string();
        let foreign_value = foreign.value().unwrap_enumerable_enum_member_string();
        if local_value.is_some() && foreign_value.is_some() {
            find_indirect_relation_field_in_model(that_model, through_path, foreign_value.unwrap(), local_value.unwrap(), context)
        } else {
            None
        }
    } else {
        None
    }
}

pub(super) fn find_relation_field_in_model<'a>(model: &'a Model, fields: Vec<&str>, references: Vec<&str>) -> Option<&'a Field> {
    for field in model.fields() {
        if field.resolved().class.is_model_relation() {
            let relation_decorator = field.decorators().find(|d| *d.identifier_path().names().last().unwrap() == "relation")?;
            let argument_list = relation_decorator.argument_list()?;
            let fields_arg = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "fields")?;
            let references_arg = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "references")?;
            let fields_ref = fields_arg.value().unwrap_enumerable_enum_member_strings()?;
            let references_ref = references_arg.value().unwrap_enumerable_enum_member_strings()?;
            if fields_ref == fields && references_ref == references {
                return Some(field);
            }
        }
    }
    None
}

pub(super) fn find_indirect_relation_field_in_model<'a>(model: &'a Model, through_path: Vec<usize>, local: &str, foreign: &str, context: &'a ResolverContext<'a>) -> Option<&'a Field> {
    for field in model.fields() {
        if field.resolved().class.is_model_relation() {
            let relation_decorator = field.decorators().find(|d| *d.identifier_path().names().last().unwrap() == "relation")?;
            let argument_list = relation_decorator.argument_list()?;
            let through = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "through")?;
            let local_arg = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "local")?;
            let foreign_arg = argument_list.arguments().find(|a| a.name().is_some() && a.name().unwrap().name() == "foreign")?;
            let local_value = local_arg.value().unwrap_enumerable_enum_member_string()?;
            let foreign_value = foreign_arg.value().unwrap_enumerable_enum_member_string()?;
            if let Some(path) = unwrap_model_path_in_expression_kind(&through.value().kind, model, context) {
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
    let Some(expr_info) = resolve_identifier(identifier, context, ReferenceSpace::Default, model.availability()) else { return None; };
    let Some(reference_info) = expr_info.reference_info() else { return None };
    if reference_info.r#type != ReferenceType::Model {
        return None;
    }
    Some(reference_info.reference.path().clone())
}

fn unwrap_model_path_in_unit<'a>(unit: &'a Unit, model: &'a Model, context: &'a ResolverContext<'a>) -> Option<Vec<usize>> {
    let expr_info = resolve_unit(unit, context, &Type::Undetermined, &btreemap! {});
    let Some(reference_info) = expr_info.reference_info() else { return None };
    if reference_info.r#type != ReferenceType::Model {
        return None;
    }
    Some(reference_info.reference.path().clone())
}

struct ShapeAvailableContext {
    has_select: bool,
    has_include: bool,
    has_where: bool,
    has_where_unique: bool,
    has_where_with_aggregates: bool,
    has_order_by: bool,
    has_serializable_scalar_fields: bool,
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
            has_serializable_scalar_fields: false,
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
        self.has_serializable_scalar_fields
    }
}

fn search_filter_type_in_std<'a>(name: &str, generics: Vec<Type>, context: &'a ResolverContext<'a>) -> Type {
    let interface = context.schema.std_source().find_node_by_string_path(
        &vec!["std", name],
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_interface_declaration().unwrap();
    Type::InterfaceObject(Reference::new(interface.path.clone(), interface.string_path.clone()), generics)
}

pub(crate) fn resolve_static_where_input_for_type<'a>(t: &Type, context: &'a ResolverContext<'a>) -> Type {
    if t.is_bool() {
        Type::Union(vec![Type::Bool, search_filter_type_in_std("BoolFilter", vec![], context)]).wrap_in_optional()
    } else if t.is_int() {
        Type::Union(vec![Type::Int, search_filter_type_in_std("Filter", vec![Type::Int], context)]).wrap_in_optional()
    } else if t.is_int64() {
        Type::Union(vec![Type::Int64, search_filter_type_in_std("Filter", vec![Type::Int64], context)]).wrap_in_optional()
    } else if t.is_float32() {
        Type::Union(vec![Type::Float32, search_filter_type_in_std("Filter", vec![Type::Float32], context)]).wrap_in_optional()
    } else if t.is_float() {
        Type::Union(vec![Type::Float, search_filter_type_in_std("Filter", vec![Type::Float], context)]).wrap_in_optional()
    } else if t.is_decimal() {
        Type::Union(vec![Type::Decimal, search_filter_type_in_std("Filter", vec![Type::Decimal], context)]).wrap_in_optional()
    } else if t.is_date() {
        Type::Union(vec![Type::Date, search_filter_type_in_std("Filter", vec![Type::Date], context)]).wrap_in_optional()
    } else if t.is_datetime() {
        Type::Union(vec![Type::DateTime, search_filter_type_in_std("Filter", vec![Type::DateTime], context)]).wrap_in_optional()
    } else if t.is_object_id() {
        Type::Union(vec![Type::ObjectId, search_filter_type_in_std("Filter", vec![Type::ObjectId], context)]).wrap_in_optional()
    } else if t.is_string() {
        Type::Union(vec![Type::String, search_filter_type_in_std("StringFilter", vec![], context)]).wrap_in_optional()
    } else if t.is_enum_variant() {
        Type::Union(vec![t.clone(), search_filter_type_in_std("EnumFilter", vec![t.clone()], context)]).wrap_in_optional()
    } else if let Some(inner) = t.as_array() {
        Type::Union(vec![t.clone(), search_filter_type_in_std("ArrayFilter", vec![inner.clone()], context)]).wrap_in_optional()
    } else if let Some(t) = t.as_optional() {
        if t.is_bool() {
            Type::Union(vec![Type::Bool, Type::Null, search_filter_type_in_std("BoolNullableFilter", vec![], context)]).wrap_in_optional()
        } else if t.is_int() {
            Type::Union(vec![Type::Int, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::Int], context)]).wrap_in_optional()
        } else if t.is_int64() {
            Type::Union(vec![Type::Int64, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::Int64], context)]).wrap_in_optional()
        } else if t.is_float32() {
            Type::Union(vec![Type::Float32, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::Float32], context)]).wrap_in_optional()
        } else if t.is_float() {
            Type::Union(vec![Type::Float, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::Float], context)]).wrap_in_optional()
        } else if t.is_decimal() {
            Type::Union(vec![Type::Decimal, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::Decimal], context)]).wrap_in_optional()
        } else if t.is_date() {
            Type::Union(vec![Type::Date, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::Date], context)]).wrap_in_optional()
        } else if t.is_datetime() {
            Type::Union(vec![Type::DateTime, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::DateTime], context)]).wrap_in_optional()
        } else if t.is_object_id() {
            Type::Union(vec![Type::ObjectId, Type::Null, search_filter_type_in_std("NullableFilter", vec![Type::ObjectId], context)]).wrap_in_optional()
        } else if t.is_string() {
            Type::Union(vec![Type::String, Type::Null, search_filter_type_in_std("StringNullableFilter", vec![], context)]).wrap_in_optional()
        }  else if t.is_enum_variant() {
            Type::Union(vec![t.clone(), Type::Null, search_filter_type_in_std("EnumNullableFilter", vec![t.clone()], context)]).wrap_in_optional()
        } else if let Some(inner) = t.as_array() {
            Type::Union(vec![t.clone(), Type::Null, search_filter_type_in_std("ArrayNullableFilter", vec![inner.clone()], context)]).wrap_in_optional()
        } else {
            t.clone()
        }
    } else {
        t.clone()
    }
}

pub(crate) fn resolve_static_where_with_aggregates_input_for_type<'a>(t: &Type, context: &'a ResolverContext<'a>) -> Type {
    if t.is_bool() {
        Type::Union(vec![Type::Bool, search_filter_type_in_std("BoolWithAggregatesFilter", vec![], context)]).wrap_in_optional()
    } else if t.is_int() {
        Type::Union(vec![Type::Int, search_filter_type_in_std("IntNumberWithAggregatesFilter", vec![Type::Int], context)]).wrap_in_optional()
    } else if t.is_int64() {
        Type::Union(vec![Type::Int64, search_filter_type_in_std("IntNumberWithAggregatesFilter", vec![Type::Int64], context)]).wrap_in_optional()
    } else if t.is_float32() {
        Type::Union(vec![Type::Float32, search_filter_type_in_std("FloatNumberWithAggregatesFilter", vec![Type::Float32], context)]).wrap_in_optional()
    } else if t.is_float() {
        Type::Union(vec![Type::Float, search_filter_type_in_std("FloatNumberWithAggregatesFilter", vec![Type::Float], context)]).wrap_in_optional()
    } else if t.is_decimal() {
        Type::Union(vec![Type::Decimal, search_filter_type_in_std("DecimalWithAggregatesFilter", vec![Type::Decimal], context)]).wrap_in_optional()
    } else if t.is_date() {
        Type::Union(vec![Type::Date, search_filter_type_in_std("AggregatesFilter", vec![Type::Date], context)]).wrap_in_optional()
    } else if t.is_datetime() {
        Type::Union(vec![Type::DateTime, search_filter_type_in_std("AggregatesFilter", vec![Type::DateTime], context)]).wrap_in_optional()
    } else if t.is_object_id() {
        Type::Union(vec![Type::ObjectId, search_filter_type_in_std("AggregatesFilter", vec![Type::ObjectId], context)]).wrap_in_optional()
    } else if t.is_string() {
        Type::Union(vec![Type::String, search_filter_type_in_std("StringWithAggregatesFilter", vec![], context)]).wrap_in_optional()
    } else if t.is_enum_variant() {
        Type::Union(vec![t.clone(), search_filter_type_in_std("EnumWithAggregatesFilter", vec![t.clone()], context)]).wrap_in_optional()
    } else if let Some(inner) = t.as_array() {
        Type::Union(vec![t.clone(), search_filter_type_in_std("ArrayWithAggregatesFilter", vec![inner.clone()], context)]).wrap_in_optional()
    } else if let Some(t) = t.as_optional() {
        if t.is_bool() {
            Type::Union(vec![Type::Bool, Type::Null, search_filter_type_in_std("BoolNullableWithAggregatesFilter", vec![], context)]).wrap_in_optional()
        } else if t.is_int() {
            Type::Union(vec![Type::Int, Type::Null, search_filter_type_in_std("IntNumberNullableWithAggregatesFilter", vec![Type::Int], context)]).wrap_in_optional()
        } else if t.is_int64() {
            Type::Union(vec![Type::Int64, Type::Null, search_filter_type_in_std("IntNumberNullableWithAggregatesFilter", vec![Type::Int64], context)]).wrap_in_optional()
        } else if t.is_float32() {
            Type::Union(vec![Type::Float32, Type::Null, search_filter_type_in_std("FloatNumberNullableWithAggregatesFilter", vec![Type::Float32], context)]).wrap_in_optional()
        } else if t.is_float() {
            Type::Union(vec![Type::Float, Type::Null, search_filter_type_in_std("FloatNumberNullableWithAggregatesFilter", vec![Type::Float], context)]).wrap_in_optional()
        } else if t.is_decimal() {
            Type::Union(vec![Type::Decimal, Type::Null, search_filter_type_in_std("DecimalNullableWithAggregatesFilter", vec![Type::Decimal], context)]).wrap_in_optional()
        } else if t.is_date() {
            Type::Union(vec![Type::Date, Type::Null, search_filter_type_in_std("NullableAggregatesFilter", vec![Type::Date], context)]).wrap_in_optional()
        } else if t.is_datetime() {
            Type::Union(vec![Type::DateTime, Type::Null, search_filter_type_in_std("NullableAggregatesFilter", vec![Type::DateTime], context)]).wrap_in_optional()
        } else if t.is_object_id() {
            Type::Union(vec![Type::ObjectId, Type::Null, search_filter_type_in_std("NullableAggregatesFilter", vec![Type::ObjectId], context)]).wrap_in_optional()
        } else if t.is_string() {
            Type::Union(vec![Type::String, Type::Null, search_filter_type_in_std("StringNullableWithAggregatesFilter", vec![], context)]).wrap_in_optional()
        } else if t.is_enum_variant() {
            Type::Union(vec![t.clone(), Type::Null, search_filter_type_in_std("EnumNullableWithAggregatesFilter", vec![t.clone()], context)]).wrap_in_optional()
        } else if let Some(inner) = t.as_array() {
            Type::Union(vec![t.clone(), Type::Null, search_filter_type_in_std("ArrayNullableWithAggregatesFilter", vec![inner.clone()], context)]).wrap_in_optional()
        }  else {
            t.clone()
        }
    } else {
        t.clone()
    }
}

pub(crate) fn resolve_static_update_input_for_type<'a>(t: &Type, atomic: bool, context: &'a ResolverContext<'a>) -> Type {
    if !atomic {
        return t.clone();
    }
    if t.is_int() {
        Type::Union(vec![Type::Int, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Int], context)]).wrap_in_optional()
    } else if t.is_int64() {
        Type::Union(vec![Type::Int64, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Int64], context)]).wrap_in_optional()
    } else if t.is_float32() {
        Type::Union(vec![Type::Float32, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Float32], context)]).wrap_in_optional()
    } else if t.is_float() {
        Type::Union(vec![Type::Float, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Float], context)]).wrap_in_optional()
    } else if t.is_decimal() {
        Type::Union(vec![Type::Decimal, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Decimal], context)]).wrap_in_optional()
    } else if let Some(inner) = t.as_array() {
        Type::Union(vec![Type::Array(Box::new(inner.clone())), search_filter_type_in_std("ArrayAtomicUpdateOperationInput", vec![inner.clone()], context)]).wrap_in_optional()
    } else if let Some(t) = t.as_optional() {
        if t.is_int() {
            Type::Union(vec![Type::Int, Type::Null, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Int], context)]).wrap_in_optional()
        } else if t.is_int64() {
            Type::Union(vec![Type::Int64, Type::Null, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Int64], context)]).wrap_in_optional()
        } else if t.is_float32() {
            Type::Union(vec![Type::Float32, Type::Null, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Float32], context)]).wrap_in_optional()
        } else if t.is_float() {
            Type::Union(vec![Type::Float, Type::Null, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Float], context)]).wrap_in_optional()
        } else if t.is_decimal() {
            Type::Union(vec![Type::Decimal, Type::Null, search_filter_type_in_std("NumberAtomicUpdateOperationInput", vec![Type::Decimal], context)]).wrap_in_optional()
        } else if let Some(inner) = t.as_array() {
            Type::Union(vec![Type::Array(Box::new(inner.clone())), Type::Null, search_filter_type_in_std("ArrayAtomicUpdateOperationInput", vec![inner.clone()], context)]).wrap_in_optional()
        } else {
            t.clone()
        }
    } else {
        t.clone()
    }
}

pub(crate) fn resolve_model_declared_shapes<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    let mut declared_shapes = IndexMap::new();
    // declared
    for declared_shape in context.schema.declared_shapes() {
        if !declared_shape.builtin {
            declared_shapes.insert(declared_shape.string_path.clone(), resolve_declared_shape(declared_shape, model));
        }
    }
    model.resolved_mut().declared_shapes = declared_shapes;
}

pub(crate) fn resolve_declared_shape(declared_shape: &SynthesizedShapeDeclaration, model: &Model) -> SynthesizedShape {
    let mut map = indexmap! {};
    let keywords_map = btreemap! {
        Keyword::SelfIdentifier => Type::ModelObject(Reference::new(model.path.clone(), model.string_path.clone())),
    };
    for field in declared_shape.static_fields() {
        map.insert(field.name().to_string(), field.type_expr().resolved().replace_keywords(&keywords_map));
    }
    for field_rule in declared_shape.dynamic_fields() {
        for model_field in model.fields() {
            if field_has_decorator_names(model_field, field_rule.decorator_identifier_path().names()) {
                if field_rule.optional {
                    map.insert(model_field.name().to_string(), model_field.type_expr().resolved().wrap_in_optional());
                } else {
                    map.insert(model_field.name().to_string(), model_field.type_expr().resolved().clone());
                }
            }
        }
    }
    SynthesizedShape::new(map)
}