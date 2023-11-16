use crate::availability::Availability;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list::jump_to_definition_in_argument_list;
use crate::r#type::r#type::Type;
use crate::traits::identifiable::Identifiable;

pub(super) fn jump_to_definition_in_enum_variant_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    enum_variant_literal: &'a EnumVariantLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
    availability: Availability,
) -> Vec<Definition> {
    if enum_variant_literal.identifier().span.contains_line_col(line_col) {
        match expect {
            Type::EnumVariant(reference) => {
                let r#enum = schema.find_top_by_path(reference.path()).unwrap().as_enum().unwrap();
                if let Some(member) = r#enum.members.iter().find(|m| m.identifier().name() == enum_variant_literal.identifier().name()) {
                    vec![Definition {
                        path: schema.source(member.source_id()).unwrap().file_path.clone(),
                        selection_span: enum_variant_literal.identifier().span,
                        target_span: member.span,
                        identifier_span: member.identifier().span,
                    }]
                } else {
                    vec![]
                }
            }
            Type::SynthesizedEnumVariantReference(reference) => {
                if let Some(reference) = reference.owner.as_model_reference() {
                    let model = schema.find_top_by_path(reference.path()).unwrap().as_model().unwrap();
                    if let Some(field) = model.fields.iter().find(|f| f.identifier().name() == enum_variant_literal.identifier().name()) {
                        vec![Definition {
                            path: schema.source(field.source_id()).unwrap().file_path.clone(),
                            selection_span: enum_variant_literal.identifier().span,
                            target_span: field.span,
                            identifier_span: field.identifier().span,
                        }]
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
            _ => vec![]
        }
    } else if let Some(argument_list) = enum_variant_literal.argument_list() {
        if argument_list.span.contains_line_col(line_col) {
            jump_to_definition_in_argument_list(
                schema,
                source,
                argument_list,
                namespace_path,
                None,
                line_col,
                availability,
            )
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}