use crate::ast::constant::Constant;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression;
use crate::r#type::r#type::Type;
use crate::search::search_availability::search_availability;
use crate::traits::resolved::Resolve;

pub(super) fn jump_to_definition_in_constant<'a>(
    schema: &'a Schema,
    source: &'a Source,
    constant: &'a Constant,
    line_col: (usize, usize),
) -> Vec<Definition> {
    let mut namespace_path: Vec<&str> = constant.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);
    if constant.expression().span().contains_line_col(line_col) {
        let undetermined = Type::Undetermined;
        return jump_to_definition_in_expression(
            schema,
            source,
            &constant.expression,
            &namespace_path,
            line_col,
            if constant.is_resolved() {
                constant.resolved().expression_resolved.r#type()
            } else {
                &undetermined
            },
            availability,
        );
    }
    vec![]
}