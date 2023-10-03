use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            start_position: (0, 0),
            end_position: (0, 0),
        }
    }
}

impl Span {

    pub(crate) fn contains(&self, position: usize) -> bool {
        position >= self.start && position <= self.end
    }

    pub(crate) fn contains_line_col_range(&self, range: ((usize, usize), (usize, usize))) -> bool {
        range.0.0 >= self.start_position.0 && range.0.1 >= self.start_position.1 &&
            range.1.0 <= self.end_position.0 && range.1.1 <= self.end_position.1
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