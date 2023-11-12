use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn};

declare_container_node!(Unit,
    pub(crate) expressions: Vec<usize>,
);

impl_container_node_defaults!(Unit);

node_children_iter!(Unit, Expression, ExpressionsIter, expressions);

impl Unit {
    node_children_iter_fn!(expressions, ExpressionsIter);
}

impl Display for Unit {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (index, item) in self.expressions().enumerate() {
            if index != 0 {
                if item.kind.as_identifier().is_some() {
                    f.write_str(".")?;
                }
            }
            Display::fmt(&item, f)?;
        }
        Ok(())
    }
}

impl Unit {

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        if self.expressions.len() != 1 {
            None
        } else {
            self.expressions().first().unwrap().unwrap_enumerable_enum_member_strings()
        }
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        if self.expressions.len() != 1 {
            None
        } else {
            self.expressions().first().unwrap().unwrap_enumerable_enum_member_string()
        }
    }
}