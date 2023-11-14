use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults_with_write};

declare_node!(AvailabilityFlagEnd);

impl_node_defaults_with_write!(AvailabilityFlagEnd, "#end");
