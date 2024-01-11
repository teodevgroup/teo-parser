use std::cell::RefCell;
use maplit::btreemap;
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

#[derive(Debug, Clone)]
pub struct PipelineResolved {
    pub items_resolved: Vec<PipelineItemResolved>,
}

impl PipelineResolved {
    pub fn new() -> Self {
        Self { items_resolved: vec![] }
    }
}

impl PipelineResolved {
    pub fn replace_generics(&self, expect: Type) -> PipelineResolved {
        if let Some((input, output)) = expect.as_pipeline() {
            let first_input = self.items_resolved.first().unwrap().input_type.clone();
            let last_output = self.items_resolved.last().unwrap().output_type.clone();
            let mut generics_map = btreemap! {};
            if first_input.contains_generics() {
                first_input.build_generics_map(&mut generics_map, input);
            }
            if last_output.contains_generics() {
                last_output.build_generics_map(&mut generics_map, output);
            }
            Self { items_resolved: self.items_resolved.iter().map(|original| PipelineItemResolved {
                input_type: original.input_type.replace_generics(&generics_map),
                output_type: original.output_type.replace_generics(&generics_map),
            }).collect() }
        } else {
            self.clone()
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipelineItemResolved {
    pub input_type: Type,
    pub output_type: Type,
}

impl Resolve<PipelineResolved> for Pipeline {

    fn resolved_ref_cell(&self) -> &RefCell<Option<PipelineResolved>> {
        &self.resolved
    }
}