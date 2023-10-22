use crate::ast::identifier::Identifier;
use crate::ast::literals::StringLiteral;
use crate::ast::span::Span;
use crate::definition::definition::Definition;

#[derive(Debug)]
pub struct Import {
    pub path: Vec<usize>,
    pub identifiers: Vec<Identifier>,
    pub source: StringLiteral,
    pub file_path: String,
    pub span: Span,
}

impl Import {

    pub fn new(path: Vec<usize>, identifiers: Vec<Identifier>, source: StringLiteral, file_path: String, span: Span) -> Self {
        Self {
            path,
            identifiers,
            source,
            file_path,
            span,
        }
    }

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}
