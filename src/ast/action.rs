use crate::ast::r#type::{TypeExpr, TypeItem};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ActionGroupDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) action_declarations: Vec<ActionDeclaration>,
}

impl ActionGroupDeclaration {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct ActionDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) input_type: TypeExpr,
    pub(crate) output_type: TypeExpr,
    pub(crate) input_format: ActionInputFormat,
}

impl ActionDeclaration {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn action_group_id(&self) -> usize {
        *self.path.get(self.path.len() - 2).unwrap()
    }
}

#[derive(Debug)]
pub(crate) enum ActionInputFormat {
    Json,
    Form,
}

impl ActionInputFormat {

    pub(crate) fn is_json(&self) -> bool {
        match self {
            ActionInputFormat::Json => true,
            _ => false,
        }
    }

    pub(crate) fn is_form(&self) -> bool {
        match self {
            ActionInputFormat::Form => true,
            _ => false,
        }
    }
}