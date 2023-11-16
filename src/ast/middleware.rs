use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::ast::doc_comment::DocComment;
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::write::Write;

declare_container_node!(MiddlewareDeclaration, named, availability,
    pub(crate) identifier: usize,
    pub(crate) argument_list_declaration: Option<usize>,
    pub(crate) comment: Option<usize>,
);

impl_container_node_defaults!(MiddlewareDeclaration, named, availability);

impl MiddlewareDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(argument_list_declaration, ArgumentListDeclaration);

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        vec![CallableVariant {
            generics_declarations: vec![],
            argument_list_declaration: self.argument_list_declaration(),
            generics_constraints: vec![],
            pipeline_input: None,
            pipeline_output: None,
        }]
    }
}

impl InfoProvider for MiddlewareDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Write for MiddlewareDeclaration {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
    fn is_block_level_element(&self) -> bool {
        true
    }
}