#[derive(Debug, Copy, Clone)]
pub struct Preferences {
    indent_size: usize,
    prefer_empty_line_before_next_block_level_element: bool,
    maximum_line_width: usize,
}

impl Preferences {

    pub fn indent_size(&self) -> usize {
        self.indent_size
    }

    pub fn prefer_empty_line_before_next_block_level_element(&self) -> bool {
        self.prefer_empty_line_before_next_block_level_element
    }

    pub fn maximum_line_width(&self) -> usize {
        self.maximum_line_width
    }
}

impl Default for Preferences {

    fn default() -> Self {
        Self {
            indent_size: 4,
            prefer_empty_line_before_next_block_level_element: true,
            maximum_line_width: 80,
        }
    }
}
