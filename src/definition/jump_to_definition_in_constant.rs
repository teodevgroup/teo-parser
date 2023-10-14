use crate::ast::constant::Constant;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression_kind;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_constant<'a>(
    schema: &'a Schema,
    source: &'a Source,
    constant: &'a Constant,
    line_col: (usize, usize),
) -> Vec<Definition> {
    let mut namespace_path: Vec<&str> = constant.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    if constant.expression.span().contains_line_col(line_col) {
        let undetermined = Type::Undetermined;
        return jump_to_definition_in_expression_kind(
            schema,
            source,
            &constant.expression,
            &namespace_path,
            line_col,
            if constant.is_resolved() {
                &constant.resolved().r#type
            } else {
                &undetermined
            }
        );
    }
    vec![]
}