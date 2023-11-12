use std::cell::RefCell;
use serde::Serialize;
use crate::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

declare_container_node!(HandlerGroupDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) handler_declarations: Vec<usize>,
);

impl_container_node_defaults!(HandlerGroupDeclaration, named, availability);

node_children_iter!(HandlerGroupDeclaration, HandlerDeclaration, HandlerDeclarationsIter, handler_declarations);

impl HandlerGroupDeclaration {

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(handler_declarations, HandlerDeclarationsIter);
}

impl InfoProvider for HandlerGroupDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

declare_container_node!(HandlerDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorators_spans: Vec<Span>,
    pub(crate) identifier: usize,
    pub(crate) input_type: usize,
    pub(crate) output_type: usize,
    pub input_format: HandlerInputFormat,
);

impl_container_node_defaults!(HandlerDeclaration, named, availability);

impl HandlerDeclaration {

    node_optional_child_fn!(comment, Comment);

    node_children_iter!(HandlerDeclaration, Decorator, DecoratorsIter, decorators);

    node_child_fn!(identifier, Identifier);

    node_child_fn!(input_type, TypeExpr);

    node_child_fn!(output_type, TypeExpr);
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum HandlerInputFormat {
    Json,
    Form,
}

impl HandlerInputFormat {

    pub fn is_json(&self) -> bool {
        match self {
            HandlerInputFormat::Json => true,
            _ => false,
        }
    }

    pub fn is_form(&self) -> bool {
        match self {
            HandlerInputFormat::Form => true,
            _ => false,
        }
    }
}

impl InfoProvider for HandlerDeclaration {
    fn namespace_skip(&self) -> usize {
        2
    }
}