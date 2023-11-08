use maplit::btreemap;
use crate::ast::data_set::{DataSet, DataSetGroup, DataSetGroupResolved, DataSetResolved};
use crate::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolve_identifier::resolve_identifier_path_with_filter;
use crate::resolver::resolve_model_shapes::{has_property_setter, is_field_readonly};
use crate::resolver::resolver_context::{ExaminedDataSetRecord, ResolverContext};
use crate::utils::top_filter::top_filter_for_model;

pub(super) fn resolve_data_set<'a>(data_set: &'a DataSet, context: &'a ResolverContext<'a>) {
    let actual_availability = context.current_availability();
    if context.has_examined_default_path(&data_set.string_path, data_set.define_availability) {
        context.insert_duplicated_identifier(data_set.identifier.span);
    }
    data_set.resolve(DataSetResolved {
        actual_availability
    });
    for group in &data_set.groups {
        resolve_data_set_group(data_set, group, context);
    }
}

fn resolve_data_set_group<'a>(data_set: &'a DataSet, group: &'a DataSetGroup, context: &'a ResolverContext<'a>) {
    if let Some(reference) = resolve_identifier_path_with_filter(&group.identifier_path, context, &top_filter_for_model(), context.current_availability()) {
        let model = context.schema.find_top_by_path(&reference).unwrap().as_model().unwrap();
        group.resolve(DataSetGroupResolved {
            model_path: reference,
            model_string_path: model.string_path.clone(),
            actual_availability: context.current_availability(),
        });
    } else {
        context.insert_diagnostics_error(group.identifier_path.span, "model not found");
    }
    // record each record names
    for record in &group.records {
        let examined = ExaminedDataSetRecord {
            data_set: data_set.string_path.clone(),
            group: group.resolved().model_string_path.clone(),
            record: record.identifier.name().to_owned(),
        };
        if context.has_examined_data_set_record(&examined) {
            context.insert_diagnostics_error(record.identifier.span, "duplicated record");
        }
        context.add_examined_data_set_record(examined);
    }
}

pub(super) fn resolve_data_set_records<'a>(data_set: &'a DataSet, context: &'a ResolverContext<'a>) {
    for group in &data_set.groups {
        if !group.is_resolved() {
            return;
        };
        let model = context.schema.find_top_by_path(&group.resolved().model_path).unwrap().as_model().unwrap();
        for record in &group.records {
            let mut used_keys = vec![];
            for (key_expression, value_expression) in &record.dictionary.expressions {
                let key_span = key_expression.span();
                let key_resolved = resolve_expression(key_expression, context, &Type::String, &btreemap! {});
                if !key_resolved.r#type.is_string() {
                    context.insert_diagnostics_error(key_span, "record key is not string");
                    return;
                }
                if key_resolved.value.is_none() {
                    context.insert_diagnostics_error(key_span, "unresolved record key");
                    return;
                }
                let key = key_resolved.value.as_ref().unwrap().as_str().unwrap();
                if used_keys.contains(&key.to_string()) {
                    context.insert_diagnostics_error(key_span, "duplicated record field");
                }
                used_keys.push(key.to_owned());
                if let Some(field) = model.fields.iter().find(|f| f.name() == key) {
                    if let Some(field_settings) = field.resolved().class.as_model_primitive_field() {
                        if field_settings.dropped {
                            context.insert_diagnostics_error(key_span, "field is dropped");
                        }
                        if is_field_readonly(field) {
                            context.insert_diagnostics_error(key_span, "field is readonly");
                        }
                        let value_span = value_expression.span();
                        let value_resolved = resolve_expression(value_expression, context, &field.type_expr.resolved(), &btreemap! {});
                        if !field.type_expr.resolved().test(value_resolved.r#type()) {
                            context.insert_diagnostics_error(value_span, format!("expect {}, found {}", field.type_expr.resolved(), value_resolved.r#type()));
                        }
                    } else if let Some(relation_settings) = field.resolved().class.as_model_relation() {
                        if let Some((model_path, model_string_path)) = field.type_expr.resolved().unwrap_optional().unwrap_array().unwrap_optional().as_model_object() {
                            let reference_model = context.schema.find_top_by_path(model_path).unwrap().as_model().unwrap();
                            let expect = Type::DataSetRecord(
                                Box::new(Type::DataSetObject(data_set.path.clone(), data_set.string_path.clone())),
                                Box::new(Type::ModelObject(reference_model.path.clone(), reference_model.string_path.clone()))
                            );
                            if field.type_expr.resolved().unwrap_optional().is_array() {
                                // to many relation
                                resolve_expression(value_expression, context, &expect.wrap_in_array(), &btreemap! {});
                            } else {
                                // to one relation
                                if field.type_expr.resolved().is_optional() {
                                    // allow null
                                    resolve_expression(value_expression, context, &expect.wrap_in_optional(), &btreemap! {});
                                } else {
                                    resolve_expression(value_expression, context, &expect, &btreemap! {});
                                }
                            }
                        } else {
                            context.insert_diagnostics_error(key_span, "relation definition is invalid");
                        }
                    } else if let Some(_) = field.resolved().class.as_model_property() {
                        if !has_property_setter(field) {
                            context.insert_diagnostics_error(key_span, "property doesn't have a setter")
                        } else if is_field_readonly(field) {
                            context.insert_diagnostics_error(key_span, "property is readonly")
                        }
                        let value_span = value_expression.span();
                        let value_resolved = resolve_expression(value_expression, context, &field.type_expr.resolved(), &btreemap! {});
                        if !field.type_expr.resolved().test(value_resolved.r#type()) {
                            context.insert_diagnostics_error(value_span, format!("expect {}, found {}", field.type_expr.resolved(), value_resolved.r#type()));
                        }
                    }
                } else {
                    context.insert_diagnostics_error(key_span, "field not found");
                }
            }
        }
    }
}
