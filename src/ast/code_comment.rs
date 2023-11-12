use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults};

declare_node!(CodeComment, lines: Vec<String>);

impl_node_defaults!(CodeComment);

impl CodeComment {

    pub fn lines(&self) -> &Vec<String> {
        &self.lines
    }
}

impl Display for CodeComment {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.lines.iter().try_for_each(|l| f.write_fmt(format_args!("// {}\n", l)))
    }
}