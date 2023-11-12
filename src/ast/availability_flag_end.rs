use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults_with_display};

declare_node!(AvailabilityFlagEnd);

impl_node_defaults_with_display!(AvailabilityFlagEnd, "#end");
