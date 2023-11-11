use crate::ast::availability::Availability;
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list_declaration::jump_to_definition_in_argument_list_declaration;
use crate::definition::jump_to_definition_in_arith_expr::jump_to_definition_in_arith_expr;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;

pub(super) fn jump_to_definition_in_enum_declaration(schema: &Schema, source: &Source, enum_declaration: &Enum, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = enum_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = enum_declaration.define_availability;
    for member in &enum_declaration.members {
        if member.span.contains_line_col(line_col) {
            return jump_to_definition_in_enum_member_declaration(
                schema,
                source,
                enum_declaration,
                member,
                &namespace_path,
                availability,
                line_col,
            );
        }
    }
    vec![]
}

pub(super) fn jump_to_definition_in_enum_member_declaration(
    schema: &Schema,
    source: &Source,
    enum_declaration: &Enum,
    enum_member_declaration: &EnumMember,
    namespace_path: &Vec<&str>,
    availability: Availability,
    line_col: (usize, usize),
) -> Vec<Definition> {
    if let Some(argument_list_declaration) = &enum_member_declaration.argument_list_declaration {
        return jump_to_definition_in_argument_list_declaration(
            schema,
            source,
            argument_list_declaration,
            &vec![],
            namespace_path,
            line_col,
            availability,
        );
    }
    if let Some(expression) = &enum_member_declaration.expression {
        if expression.span().contains_line_col(line_col) {
            if let Some(arith_expr) = expression.as_arith_expr() {
                return jump_to_definition_in_arith_expr(
                    schema,
                    source,
                    arith_expr,
                    namespace_path,
                    line_col,
                    &Type::EnumVariant(Reference::new(enum_declaration.path.clone(), enum_declaration.string_path.clone())),
                    availability,
                );
            } else {
                return vec![];
            }
        }
    }
    vec![]
}