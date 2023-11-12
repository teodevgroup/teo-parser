use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults};

declare_node!(IntSubscript, pub index: usize);

impl_node_defaults!(IntSubscript);

impl Display for IntSubscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(".")?;
        Display::fmt(&self.index, f)
    }
}
