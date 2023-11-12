use std::fmt::{Display, Formatter};
use crate::declare_node;

declare_node!(AvailabilityFlag, name: String);

impl Display for AvailabilityFlag {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("#if available({})", self.name))
    }
}