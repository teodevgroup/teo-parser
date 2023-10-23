use crate::ast::availability::Availability;
use crate::ast::identifiable::Identifiable;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::definition::definition::Definition;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_enum_variant_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    enum_variant_literal: &'a EnumVariantLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
) -> Vec<Definition> {
    if enum_variant_literal.identifier.span.contains_line_col(line_col) {
        let top = match expect {
            Type::EnumVariant(enum_path, _) => {
                schema.find_top_by_path(enum_path)
            }
            Type::ModelRelations(model, _) => {
                schema.find_top_by_path(model.as_model_object().unwrap().0)
            }
            Type::ModelDirectRelations(model, _) => {
                schema.find_top_by_path(model.as_model_object().unwrap().0)
            }
            Type::ModelScalarFields(model, _) => {
                schema.find_top_by_path(model.as_model_object().unwrap().0)
            }
            Type::ModelScalarFieldsWithoutVirtuals(model, _) => {
                schema.find_top_by_path(model.as_model_object().unwrap().0)
            }
            Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(model, _) => {
                schema.find_top_by_path(model.as_model_object().unwrap().0)
            }
            _ => None
        };
        if let Some(top) = top {
            match top {
                Top::Enum(e) => {
                    if let Some(member) = e.members.iter().find(|m| m.identifier.name() == enum_variant_literal.identifier.name()) {
                        return vec![Definition {
                            path: schema.source(member.source_id()).unwrap().file_path.clone(),
                            selection_span: enum_variant_literal.identifier.span,
                            target_span: member.span,
                            identifier_span: member.identifier.span,
                        }];
                    } else {
                        return vec![];
                    }
                },
                Top::Model(m) => {
                    if let Some(field) = m.fields.iter().find(|f| f.identifier.name() == enum_variant_literal.identifier.name()) {
                        return vec![Definition {
                            path: schema.source(field.source_id()).unwrap().file_path.clone(),
                            selection_span: enum_variant_literal.identifier.span,
                            target_span: field.span,
                            identifier_span: field.identifier.span,
                        }];
                    } else {
                        return vec![];
                    }
                },
                _ => return vec![],
            }
        } else {
            return vec![];
        }
    }
    vec![]
}