use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier_path::IdentifierPath;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::traits::resolved::Resolve;

declare_container_node!(Decorator,
    identifier_path: usize,
    argument_list: Option<usize>,
    resolved: RefCell<Option<Vec<usize>>>,
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
