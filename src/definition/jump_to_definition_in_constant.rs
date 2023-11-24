use crate::ast::constant_declaration::ConstantDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression;
use crate::definition::jump_to_definition_in_type_expr::jump_to_definition_in_type_expr_kind;
use crate::r#type::r#type::Type;
use crate::search::search_availability::search_availability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;
use crate::traits::node_trait::NodeTrait;

pub(super) fn jump_to_definition_in_constant<'a>(
    schema: &'a Schema,
    source: &'a Source,
    constant: &'a ConstantDeclaration,
    line_col: (usize, usize),
) -> Vec<Definition> {
    let namespace_path: Vec<&str> = constant.namespace_str_path();
    let availability = search_availability(schema, source, &namespace_path);
    if let Some(type_expr) = constant.type_expr() {
        if type_expr.span().contains_line_col(line_col) {
            jump_to_definition_in_type_expr_kind(
                schema,
                source,
                &type_expr.kind,
                &namespace_path,
                line_col,
                &vec![],
                availability,
            )
        } else {
            vec![]
        }
    } else if constant.expression().span().contains_line_col(line_col) {
        let undetermined = Type::Undetermined;
        return jump_to_definition_in_expression(
            schema,
            source,
            constant.expression(),
            &namespace_path,
            line_col,
            if constant.is_resolved() {
                constant.resolved().r#type()
            } else {
                &undetermined
            },
            availability,
        );
    }
    vec![]
}