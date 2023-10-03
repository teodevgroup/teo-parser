use std::fmt::{Display, Formatter};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) start_position: (usize, usize),
    pub(crate) end_position: (usize, usize),
}

impl Default for Span {

    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            start_position: (1, 1),
            end_position: (1, 1),
        }
    }
}

impl Span {

    pub(crate) fn contains(&self, position: usize) -> bool {
        position >= self.start && position <= self.end
    }

    pub(crate) fn contains_line_col(&self, line_col: (usize, usize)) -> bool {
        line_col.0 >= self.start_position.0 &&
            line_col.0 <= self.end_position.0 &&
            if line_col.0 == self.start_position.0 { line_col.1 >= self.start_position.1 } else { true } &&
            if line_col.0 == self.end_position.0 { line_col.1 <= self.end_position.1 } else { true }
    }

    pub(crate) fn overlaps(&self, other: Span) -> bool {
        self.contains(other.start) || self.contains(other.end)
    }
}

impl Display for Span {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{}:{} - {}:{}",
            self.start_position.0,
            self.start_position.1,
            self.end_position.0,
            self.end_position.1
        ))
    }
}