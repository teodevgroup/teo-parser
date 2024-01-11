use std::cell::RefCell;
use crate::ast::unit::Unit;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::r#type::Type;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(Pipeline,
    pub(crate) unit: usize,
    pub resolved: RefCell<Option<PipelineResolved>>,
);

impl_container_node_defaults!(Pipeline);

impl Pipeline {
    node_child_fn!(unit, Unit);
}

impl Write for Pipeline {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}

#[derive(Debug)]
pub struct PipelineResolved {
    pub items_resolved: Vec<PipelineItemResolved>,
}

#[derive(Debug)]
pub struct PipelineItemResolved {
    pub input_type: Type,
    pub output_type: Type,
}

impl Resolve<PipelineResolved> for Pipeline {

    fn resolved_ref_cell(&self) -> &RefCell<Option<PipelineResolved>> {
        &self.resolved
    }
}