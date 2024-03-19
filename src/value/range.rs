use std::fmt::{Display, Formatter};
use serde::Serialize;
use crate::value::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Range {
    pub closed: bool,
    pub start: Box<Value>,
    pub end: Box<Value>,
}

impl Display for Range {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.start.as_ref(), f)?;
        if self.closed {
            f.write_str("...")?;
        } else {
            f.write_str("..")?;
        }
        Display::fmt(self.end.as_ref(), f)
    }
}