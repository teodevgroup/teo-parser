use std::fmt::{Display, Formatter};
use crate::ast::argument::Argument;
use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::{declare_container_node};

declare_container_node!(ArgumentList);

impl ArgumentList {

    fn arguments(&self) -> Vec<&Argument> {
        self.children.iter().filter_map(|c| c.as_argument()).collect()
    }
}

impl Default for ArgumentList {

    fn default() -> Self {

        Self { children: Vec::default(), path: Vec::default(), span: Span::default() }
    }
}

impl Display for ArgumentList {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        let len = self.arguments.len();
        for (index, expression) in self.arguments.iter().enumerate() {
            Display::fmt(expression, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str(")")
    }
}

impl crate::traits::identifiable::Identifiable for ArgumentList {

    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl crate::traits::node_trait::NodeTrait for ArgumentList {

    fn span(&self) -> Span {
        self.span
    }

    fn children(&self) -> Option<&Vec<Node>> {
        Some(&self.children)
    }
}