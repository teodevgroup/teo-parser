use crate::ast::identifier::Identifier;
use crate::ast::interface_type::InterfaceType;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ActionGroupDeclaration {
    pub(crate) path: Vec<usize>,
    pub(crate) identifier: Identifier,
    pub(crate) actions: Vec<ActionDeclaration>,
    pub(crate) span: Span,
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
    pub(crate) path: Vec<usize>,
    pub(crate) identifier: Identifier,
    pub(crate) input_type: InterfaceType,
    pub(crate) output_type: InterfaceType,
    pub(crate) input_format: ActionInputFormat,
    pub(crate) span: Span,
    pub(crate) resolved_input_interface: Option<(usize, usize)>,
    // pub(crate) resolved_input_shape: Option<ResolvedInterfaceField>,
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