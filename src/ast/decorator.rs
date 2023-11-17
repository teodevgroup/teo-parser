use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier_path::IdentifierPath;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(Decorator,
    pub(crate) identifier_path: usize,
    pub(crate) argument_list: Option<usize>,
    pub(crate) resolved: RefCell<Option<Vec<usize>>>,
);

impl_container_node_defaults!(Decorator);

impl Decorator {

    node_child_fn!(identifier_path, IdentifierPath);

    node_optional_child_fn!(argument_list, ArgumentList);
}

impl Resolve<Vec<usize>> for Decorator {
    fn resolved_ref_cell(&self) -> &RefCell<Option<Vec<usize>>> {
        &self.resolved
    }
}

impl Write for Decorator {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}