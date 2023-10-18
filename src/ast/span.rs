use std::fmt::{Display, Formatter};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub start_position: (usize, usize),
    pub end_position: (usize, usize),
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

    pub fn contains(&self, position: usize) -> bool {
        position >= self.start && position <= self.end
    }

    pub fn contains_line_col(&self, line_col: (usize, usize)) -> bool {
        line_col.0 >= self.start_position.0 &&
            line_col.0 <= self.end_position.0 &&
            if line_col.0 == self.start_position.0 { line_col.1 >= self.start_position.1 } else { true } &&
            if line_col.0 == self.end_position.0 { line_col.1 <= self.end_position.1 } else { true }
    }

    pub fn overlaps(&self, other: Span) -> bool {
        self.contains(other.start) || self.contains(other.end)
    }

    pub fn merge(&self, other: &Span) -> Span {
        Span {
            start: if self.start < other.start { self.start } else { other.start },
            end: if self.end < other.end { other.end } else { self.end },
            start_position: if self.start < other.start { self.start_position } else { other.start_position },
            end_position: if self.end < other.end { other.end_position } else { self.end_position },
        }
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