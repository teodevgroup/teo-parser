use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier::Identifier;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression_kind;

pub(super) fn jump_to_definition_in_argument_list<'a>(
    schema: &'a Schema,
    source: &'a Source,
    argument_list: &'a ArgumentList,
    namespace_path: &Vec<&'a str>,
    callable_reference: Vec<usize>,
    line_col: (usize, usize),
) -> Vec<Definition> {
    for argument in &argument_list.arguments {
        if argument.span.contains_line_col(line_col) {
            return jump_to_definition_in_argument(
                schema,
                source,
                argument,
                namespace_path,
                callable_reference,
                line_col,
            )
        }
    }
    vec![]
}

pub(super) fn jump_to_definition_in_argument<'a>(
    schema: &'a Schema,
    source: &'a Source,
    argument: &'a Argument,
    namespace_path: &Vec<&'a str>,
    callable_reference: Vec<usize>,
    line_col: (usize, usize),
) -> Vec<Definition> {
    if let Some(name) = &argument.name {
        if name.span.contains_line_col(line_col) {
            return jump_to_definition_in_argument_name(
                schema,
                source,
                name,
                namespace_path,
                callable_reference,
                line_col,
            );
        }
    }
    if argument.value.span().contains_line_col(line_col) {
        return jump_to_definition_in_expression_kind(
            schema,
            source,
            &argument.value.kind,
            namespace_path,
            line_col,
            argument.value.resolved()
        );
    }
    vec![]
}

pub(super) fn jump_to_definition_in_argument_name<'a>(
    schema: &'a Schema,
    source: &'a Source,
    name: &'a Identifier,
    namespace_path: &Vec<&'a str>,
    callable_reference: Vec<usize>,
    line_col: (usize, usize),
) -> Vec<Definition> {
    vec![]
}