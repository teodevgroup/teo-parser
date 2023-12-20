use serde::Serialize;
use crate::ast::doc_comment::DocComment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::empty_decorator::EmptyDecorator;
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::write::Write;

declare_container_node!(HandlerGroupDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) handler_declarations: Vec<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorators: Vec<usize>,
    pub(crate) unattached_decorators: Vec<usize>,
);

impl_container_node_defaults!(HandlerGroupDeclaration, named, availability);

node_children_iter!(HandlerGroupDeclaration, HandlerDeclaration, HandlerDeclarationsIter, handler_declarations);

node_children_iter!(HandlerGroupDeclaration, Decorator, GroupDecoratorsIter, decorators);

node_children_iter!(HandlerGroupDeclaration, Decorator, GroupUnattachedDecoratorsIter, unattached_decorators);

node_children_iter!(HandlerGroupDeclaration, EmptyDecorator, GroupEmptyDecoratorsIter, empty_decorators);

impl HandlerGroupDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(handler_declarations, HandlerDeclarationsIter);

    node_children_iter_fn!(decorators, GroupDecoratorsIter);

    node_children_iter_fn!(empty_decorators, GroupEmptyDecoratorsIter);

    node_children_iter_fn!(unattached_decorators, GroupUnattachedDecoratorsIter);
}

impl InfoProvider for HandlerGroupDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

declare_container_node!(HandlerDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorators: Vec<usize>,
    pub(crate) identifier: usize,
    pub(crate) input_type: Option<usize>,
    pub(crate) output_type: usize,
    pub input_format: HandlerInputFormat,
    pub nonapi: bool,
    pub inside_group: bool,
);

impl_container_node_defaults!(HandlerDeclaration, named, availability);

node_children_iter!(HandlerDeclaration, Decorator, DecoratorsIter, decorators);

node_children_iter!(HandlerDeclaration, EmptyDecorator, EmptyDecoratorsIter, empty_decorators);

impl HandlerDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_children_iter_fn!(decorators, DecoratorsIter);

    node_children_iter_fn!(empty_decorators, EmptyDecoratorsIter);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(input_type, TypeExpr);

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
        if self.inside_group {
            2
        } else {
            1
        }
    }
}

impl Write for HandlerGroupDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}

impl Write for HandlerDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}