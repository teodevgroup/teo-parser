use crate::ast::expression::Expression;
use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::empty_dot::EmptyDot;
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(Unit,
    pub(crate) expressions: Vec<usize>,
    pub(crate) empty_dot: Option<usize>,
);

impl_container_node_defaults!(Unit);

node_children_iter!(Unit, Expression, ExpressionsIter, expressions);

impl Unit {

    node_optional_child_fn!(empty_dot, EmptyDot);

    node_children_iter_fn!(expressions, ExpressionsIter);

    pub fn expression_at(&self, idx: usize) -> Option<&Expression> {
        self.expressions.get(idx).map(|idx| self.children.get(idx)).flatten().map(|n| n.as_expression()).flatten()
    }

    pub fn last_expression(&self) -> Option<&Expression> {
        self.expressions.last().map(|idx| self.children.get(idx)).flatten().map(|n| n.as_expression()).flatten()
    }
}

impl Write for Unit {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}

impl Unit {

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        if self.expressions.len() != 1 {
            None
        } else {
            self.expressions().next().unwrap().unwrap_enumerable_enum_member_strings()
        }
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        if self.expressions.len() != 1 {
            None
        } else {
            self.expressions().next().unwrap().unwrap_enumerable_enum_member_string()
        }
    }
}