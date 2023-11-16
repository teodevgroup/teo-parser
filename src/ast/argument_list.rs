use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::ast::argument::Argument;
use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn};
use crate::format::Writer;
use crate::traits::node_trait::NodeTrait;
use crate::traits::write::Write;

declare_container_node!(ArgumentList, pub(crate) arguments: Vec<usize>);

impl_container_node_defaults!(ArgumentList);

node_children_iter!(ArgumentList, Argument, ArgumentsIter, arguments);

impl ArgumentList {

    node_children_iter_fn!(arguments, ArgumentsIter);
}

impl Default for ArgumentList {

    fn default() -> Self {

        Self { children: BTreeMap::default(), arguments: Vec::default(), path: Vec::default(), span: Span::default() }
    }
}

impl Write for ArgumentList {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}