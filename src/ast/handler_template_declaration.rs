use crate::ast::doc_comment::DocComment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::handler::{HandlerDeclaration, HandlerInputFormat};
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::write::Write;

declare_container_node!(HandlerTemplateDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) input_type: Option<usize>,
    pub(crate) output_type: usize,
    pub input_format: HandlerInputFormat,
    pub nonapi: bool,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorators: Vec<usize>,
);

impl_container_node_defaults!(HandlerTemplateDeclaration, named, availability);

node_children_iter!(HandlerTemplateDeclaration, Decorator, DecoratorsIter, decorators);

node_children_iter!(HandlerTemplateDeclaration, Decorator, EmptyDecoratorsIter, empty_decorators);

impl HandlerTemplateDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(decorators, DecoratorsIter);

    node_children_iter_fn!(empty_decorators, EmptyDecoratorsIter);

    node_optional_child_fn!(input_type, TypeExpr);

    node_child_fn!(output_type, TypeExpr);
}

impl InfoProvider for HandlerTemplateDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Write for HandlerTemplateDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}