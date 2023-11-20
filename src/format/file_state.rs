use crate::format::Preferences;

#[derive(Copy, Clone, Debug)]
pub(super) struct FileState {
    pub(super) indent_level: usize,
    pub(super) previous_node_requires_whitespace_after: bool,
    pub(super) previous_node_is_decorator: bool,
    pub(super) is_at_newline: bool,
    pub(super) line_remaining_length: i64,
}

impl FileState {

    pub(super) fn new(preferences: &Preferences) -> Self {
        Self {
            indent_level: 0,
            previous_node_requires_whitespace_after: false,
            previous_node_is_decorator: false,
            is_at_newline: true,
            line_remaining_length: preferences.maximum_line_width() as i64,
        }
    }
}