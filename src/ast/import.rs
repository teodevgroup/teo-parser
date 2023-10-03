use crate::ast::identifier::Identifier;
use crate::ast::literals::StringLiteral;
use crate::ast::span::Span;
use crate::definition::definition::Definition;
use crate::definition::definition_context::DefinitionContext;

#[derive(Debug)]
pub(crate) struct Import {
    pub(crate) path: Vec<usize>,
    pub(crate) identifiers: Vec<Identifier>,
    pub(crate) source: StringLiteral,
    pub(crate) file_path: String,
    pub(crate) span: Span,
}

impl Import {

    pub(crate) fn new(path: Vec<usize>, identifiers: Vec<Identifier>, source: StringLiteral, file_path: String, span: Span) -> Self {
        Self {
            path,
            identifiers,
            source,
            file_path,
            span,
        }
    }

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn jump_to_definition(&self, context: &DefinitionContext, line_col_range: ((usize, usize), (usize, usize))) -> Vec<Definition> {
        if self.source.span.contains_line_col_range(line_col_range) {
            if !self.file_path.starts_with("(builtin)") {
                vec![
                    Definition {
                        path: self.file_path.clone(),
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
}
