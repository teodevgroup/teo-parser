
use crate::ast::literals::ArrayLiteral;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::ast::middleware::MiddlewareType;
use crate::format::Writer;
use crate::traits::info_provider::InfoProvider;
use crate::traits::write::Write;

declare_container_node!(UseMiddlewaresBlock, named, availability,
    pub(crate) array_literal: usize,
    pub(crate) middleware_type: MiddlewareType,
);

impl_container_node_defaults!(UseMiddlewaresBlock, named, availability);

impl UseMiddlewaresBlock {
    node_child_fn!(array_literal, ArrayLiteral);
}

impl InfoProvider for UseMiddlewaresBlock {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Write for UseMiddlewaresBlock {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}