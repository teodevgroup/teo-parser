#[derive(Clone)]
pub(super) struct State {
    pub(super) processing_path: Vec<usize>,
    pub(super) indent_level: usize,
    pub(super) previous_node_requires_whitespace_after: bool,
    pub(super) previous_node_is_decorator: bool,
    pub(super) is_at_newline: bool,
    pub(super) line_remaining_length: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            processing_path: vec![],
            indent_level: 0,
            previous_node_requires_whitespace_after: false,
            previous_node_is_decorator: false,
            is_at_newline: true,
            line_remaining_length: 0,
        }
    }
}

impl State {
    fn set_indent_level(&mut self, indent_level: usize) {
        if indent_level > 0 {
            self.indent_level = indent_level;
        }
    }

    fn increase_indent_level(&mut self) {
        self.indent_level += 1;
    }

    fn decrease_indent_level(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }
}