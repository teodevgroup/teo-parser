#[derive(Debug, Copy, Clone)]
pub struct Preferences {
    indent_size: usize,
    prefer_empty_line_before_next_enum_member_declaration:bool,
    prefer_empty_line_before_next_block_level_element: bool,
    maximum_line_width: usize,
    insert_new_line_at_the_end_of_file: bool,
}

impl Preferences {

    pub fn indent_size(&self) -> usize {
        self.indent_size
    }

    pub fn prefer_empty_line_before_next_enum_member_declaration(&self) -> bool {
        self.prefer_empty_line_before_next_enum_member_declaration
    }

    pub fn prefer_empty_line_before_next_block_level_element(&self) -> bool {
        self.prefer_empty_line_before_next_block_level_element
    }

    pub fn maximum_line_width(&self) -> usize {
        self.maximum_line_width
    }

    pub fn insert_new_line_at_the_end_of_file(&self) -> bool {
        self.insert_new_line_at_the_end_of_file
    }
}

impl Default for Preferences {

    fn default() -> Self {
        Self {
            indent_size: 4,
            prefer_empty_line_before_next_enum_member_declaration: false,
            prefer_empty_line_before_next_block_level_element: true,
            maximum_line_width: 80,
            insert_new_line_at_the_end_of_file: true,
        }
    }
}
