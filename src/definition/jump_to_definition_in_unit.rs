use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression_kind;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_unit<'a>(
    schema: &'a Schema,
    source: &'a Source,
    unit: &'a Unit,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
) -> Vec<Definition> {
    if unit.expressions.len() == 1 {
        jump_to_definition_in_expression_kind(
            schema,
            source,
            unit.expressions.get(0).unwrap(),
            namespace_path,
            line_col,
            expect,
        )
    } else {
        vec![]
    }
}