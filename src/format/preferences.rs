#[derive!(Debug)]
pub struct Preferences {
    indent_size: usize,
    prefer_empty_line_before_next_block_level_element: bool,
}

impl Preferences {

    pub fn indent_size(&self) -> usize {
        self.indent_size
    }

    pub fn prefer_empty_line_before_next_block_level_element(&self) -> bool {
        self.prefer_empty_line_before_next_block_level_element
    }
}

impl Default for Preferences {

    fn default() -> Self {
        Self {
            indent_size: 4,
            prefer_empty_line_before_next_block_level_element: true,
        }
    }
}
