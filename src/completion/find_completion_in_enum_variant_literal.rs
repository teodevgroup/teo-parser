use crate::ast::data_set::DataSet;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::availability::Availability;
use crate::completion::collect_argument_list_names::collect_argument_list_names_from_argument_list_declaration;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::documentation_from_comment;
use crate::completion::find_completion_in_argument_list::find_completion_in_argument_list;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::r#type::Type;
use crate::search::search_identifier_path::search_identifier_path_names_with_filter_to_top_multiple;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn find_completion_in_enum_variant_literal(schema: &Schema, source: &Source, enum_variant_literal: &EnumVariantLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type, availability: Availability) -> Vec<CompletionItem> {
    println!("see expect: {}", expect);
    if enum_variant_literal.identifier().span.contains_line_col(line_col) {
        match expect {
            Type::EnumVariant(reference) => {
                let enum_definition = schema.find_top_by_path(reference.path()).unwrap().as_enum().unwrap();
                enum_definition.members().map(|member| CompletionItem {
                    label: member.name().to_owned(),
                    namespace_path: Some(enum_definition.str_path().join(".")),
                    documentation: documentation_from_comment(member.comment()),
                    detail: None,
                }).collect()
            },
            Type::SynthesizedEnum(synthesized_enum) => {
                completion_item_from_synthesized_enum(synthesized_enum)
            },
            Type::SynthesizedEnumReference(synthesized_enum_reference) => {
                if let Some(synthesized_enum) = synthesized_enum_reference.fetch_synthesized_definition(schema) {
                    completion_item_from_synthesized_enum(synthesized_enum)
                } else {
                    vec![]
                }
            }
            Type::DataSetRecord(dataset_object, model_object) => {
                let dataset_string_path = dataset_object.as_data_set_object().unwrap();
                let model_reference = model_object.as_model_object().unwrap();
                let data_sets_found: Vec<&DataSet> = search_identifier_path_names_with_filter_to_top_multiple(
                    &dataset_string_path.iter().map(AsRef::as_ref).collect(),
                    schema,
                    source,
                    namespace_path,
                    &top_filter_for_reference_type(ReferenceSpace::Default),
                    availability,
                ).iter().map(|node| node.as_data_set().unwrap()).collect();
                let mut records = vec![];
                for data_set in data_sets_found {
                    if let Some(group) = data_set.groups().find(|g| g.resolved() == model_reference) {
                        for record in group.records() {
                            records.push(CompletionItem {
                                label: record.identifier().name().to_owned(),
                                namespace_path: Some(data_set.namespace_str_path().join(".")),
                                documentation: None,
                                detail: None,
                            });
                        }
                    }
                }
                records
            }
            _ => vec![]
        }
    } else if let Some(argument_list) = enum_variant_literal.argument_list() {
        if argument_list.span.contains_line_col(line_col) {
            match expect {
                Type::EnumVariant(reference) => {
                    let enum_definition = schema.find_top_by_path(reference.path()).unwrap().as_enum().unwrap();
                    if let Some(member) = enum_definition.members().find(|m| m.identifier().name() == enum_variant_literal.identifier().name()) {
                        if let Some(argument_list_declaration) = member.argument_list_declaration() {
                            find_completion_in_argument_list(schema, source, argument_list, line_col, namespace_path, availability, vec![collect_argument_list_names_from_argument_list_declaration(
                                argument_list_declaration
                            )])
                        } else {
                            find_completion_in_argument_list(schema, source, argument_list, line_col, namespace_path, availability, vec![])
                        }
                    } else {
                        find_completion_in_argument_list(schema, source, argument_list, line_col, namespace_path, availability, vec![])
                    }
                },
                _ => {
                    find_completion_in_argument_list(schema, source, argument_list, line_col, namespace_path, availability, vec![])
                }
            }
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}

fn completion_item_from_synthesized_enum(synthesized_enum: &SynthesizedEnum) -> Vec<CompletionItem> {
    synthesized_enum.members.values().map(|member| CompletionItem {
        label: member.name.clone(),
        namespace_path: None,
        documentation: documentation_from_comment(member.comment.as_ref()),
        detail: None,
    }).collect()
}