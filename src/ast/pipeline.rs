use std::fmt::{Display, Formatter};
use crate::ast::unit::Unit;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};

declare_container_node!(Pipeline, pub(crate) unit: usize);

impl_container_node_defaults!(Pipeline);

impl Pipeline {
    node_child_fn!(unit, Unit);
}

impl Display for Pipeline {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("$")?;
        Display::fmt(&self.unit, f)
    }
}
