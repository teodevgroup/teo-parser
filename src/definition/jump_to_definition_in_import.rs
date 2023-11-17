use crate::ast::import::Import;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::definition::definition::Definition;

pub(super) fn jump_to_definition_in_import(_schema: &Schema, _source: &Source, import: &Import, line_col: (usize, usize)) -> Vec<Definition> {
    if import.source.span.contains_line_col(line_col) {
        if !import.file_path.starts_with("(builtin)") {
            vec![
                Definition {
                    path: import.file_path.clone(),
                    selection_span: import.source.span,
                    target_span: Span::default(),
                    identifier_span: Span::default(),
                }
            ]
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}
