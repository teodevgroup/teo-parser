use std::sync::Arc;
use crate::ast::decorator::Decorator;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::definition::definition::Definition;

pub(super) fn jump_to_definition_in_decorator<'a>(
    schema: &'a Schema,
    source: &'a Source,
    decorator: &'a Decorator,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    filter: &Arc<dyn Fn(&Top) -> bool>,
) -> Vec<Definition> {
    let mut user_typed_spaces = vec![];
    for identifier in decorator.identifier_path.identifiers.iter() {
        if identifier.span.contains_line_col(line_col) {
            break
        } else {
            user_typed_spaces.push(identifier.name());
        }
    }
    let mut combined_namespace_path = namespace_path.clone();
    combined_namespace_path.extend(user_typed_spaces);
    //let top = source.find_top_by_path(&combined_namespace_path).unwrap();
    vec![]
}