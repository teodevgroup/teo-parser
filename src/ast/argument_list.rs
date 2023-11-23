use crate::ast::argument::Argument;
use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn};
use crate::ast::partial_argument::PartialArgument;
use crate::format::Writer;
use crate::traits::node_trait::NodeTrait;
use crate::traits::write::Write;

declare_container_node!(ArgumentList, pub(crate) arguments: Vec<usize>, pub(crate) partial_arguments: Vec<usize>);

impl_container_node_defaults!(ArgumentList);

node_children_iter!(ArgumentList, Argument, ArgumentsIter, arguments);

node_children_iter!(ArgumentList, PartialArgument, PartialArgumentsIter, partial_arguments);

impl ArgumentList {

    node_children_iter_fn!(arguments, ArgumentsIter);

    node_children_iter_fn!(partial_arguments, PartialArgumentsIter);
}

impl Write for ArgumentList {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}