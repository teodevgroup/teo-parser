use serde::Serialize;
use crate::ast::schema::Schema;
use crate::ast::span::Span;
use crate::definition::definition_context::DefinitionContext;

#[derive(Debug, Serialize)]
pub struct Definition {
    pub(crate) path: String,
    pub(crate) selection_span: Span,
    pub(crate) target_span: Span,
    pub(crate) identifier_span: Span,
}

pub fn jump_to_definition(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<Definition> {

    if let Some(source) = schema.sources().iter().find(|s| s.file_path.as_str() == file_path) {
        let mut context = DefinitionContext::new(schema, source);
        return source.jump_to_definition(&mut context, line_col);
    }
    vec![]
}