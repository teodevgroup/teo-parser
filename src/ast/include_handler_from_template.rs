use std::cell::RefCell;
use crate::ast::doc_comment::DocComment;
use crate::ast::decorator::Decorator;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::identifier_path::IdentifierPath;
use crate::format::Writer;
use crate::r#type::Type;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(IncludeHandlerFromTemplate, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier_path: usize,
    pub(crate) as_identifier: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorators: Vec<usize>,
    pub(crate) resolved: RefCell<Option<IncludeHandlerFromTemplateResolved>>,
);

impl_container_node_defaults!(IncludeHandlerFromTemplate, availability);

node_children_iter!(IncludeHandlerFromTemplate, Decorator, DecoratorsIter, decorators);

node_children_iter!(IncludeHandlerFromTemplate, Decorator, EmptyDecoratorsIter, empty_decorators);

impl IncludeHandlerFromTemplate {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier_path, IdentifierPath);

    node_optional_child_fn!(as_identifier, Identifier);

    node_children_iter_fn!(decorators, DecoratorsIter);

    node_children_iter_fn!(empty_decorators, EmptyDecoratorsIter);
}

impl NamedIdentifiable for IncludeHandlerFromTemplate {

    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }

    fn name(&self) -> &str {
        if let Some(identifier) = self.as_identifier() {
            identifier.name()
        } else {
            self.identifier_path().identifiers().last().unwrap().name()
        }
    }
}

impl InfoProvider for IncludeHandlerFromTemplate {
    fn namespace_skip(&self) -> usize {
        2
    }
}

impl Write for IncludeHandlerFromTemplate {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}

impl Resolve<IncludeHandlerFromTemplateResolved> for IncludeHandlerFromTemplate {
    fn resolved_ref_cell(&self) -> &RefCell<Option<IncludeHandlerFromTemplateResolved>> {
        &self.resolved
    }
}

#[derive(Debug)]
pub struct IncludeHandlerFromTemplateResolved {
    pub input_type: Option<Type>,
    pub output_type: Type,
    pub template_path: Vec<String>,
}