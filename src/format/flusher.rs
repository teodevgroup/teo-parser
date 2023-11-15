use crate::format::command::{BranchCommand, Command};
use crate::format::file_state::FileState;
use crate::format::flusher_state::FlusherState;
use crate::format::{Preferences, Writer};

pub(super) struct Flusher<'a> {
    commands: &'a Vec<Command<'a>>,
    file_state: FileState,
    flusher_state: FlusherState,
    preferences: Preferences,
}

impl<'a> Flusher<'a> {

    pub(super) fn new_from_beginning(commands: &'a Vec<Command<'a>>, preferences: Preferences) -> Self {
        let file_state = FileState::new(&preferences);
        Self::new(commands, file_state, preferences)
    }

    pub(super) fn new(commands: &'a Vec<Command<'a>>, file_state: FileState, preferences: Preferences) -> Self {
        let flusher_state = FlusherState::default();
        Self { commands, flusher_state, file_state, preferences }
    }

    pub(super) fn flush(&mut self) -> String {
        let mut buffer = "".to_owned();
        loop {
            if self.is_finished() { break }
            self.write_next_command(&mut buffer);
        }
        buffer
    }

    fn is_finished(&self) -> bool {
        self.flusher_state.processing_index >= self.commands.len()
    }

    fn write_next_command(&mut self, buffer: &mut String) {
        let command = self.commands.get(self.flusher_state.processing_index).unwrap();
        if command.node().is_block_start() {
            self.write_block(buffer);
        } else {
            self.write_non_block_command(buffer);
        }
    }

    fn reset_state_to_newline(&mut self) {
        self.file_state.is_at_newline = true;
        self.file_state.line_remaining_length = self.preferences.maximum_line_width();
    }

    fn write_block(&mut self, buffer: &mut String) {

        // retrieve command
        let command = self.commands.get(self.flusher_state.processing_index).unwrap();

        // figure out can we write in one line
        let mut index = self.flusher_state.processing_index + 1;
        let mut block_level = 0;
        let mut captured_line_remaining_length = self.file_state.line_remaining_length;
        loop {
            if index >= self.commands.len() { break }
            let command = self.commands.get(index).unwrap();

            index += 1;
        }
    }

    fn write_non_block_command(&mut self, buffer: &mut String) {

        // retrieve command
        let command = self.commands.get(self.flusher_state.processing_index).unwrap();

        // capture newline status
        let is_at_newline_after_indented = self.file_state.is_at_newline;

        // insert indentations if needed
        if self.file_state.is_at_newline {
            if self.file_state.indent_level != 0 {
                let whitespace_count = self.file_state.indent_level * self.preferences.indent_size();
                self.file_state.line_remaining_length -= whitespace_count;
                buffer.push_str(&" ".repeat(whitespace_count));
            }
            self.file_state.is_at_newline = false;
        }

        // insert leading whitespace if needed
        if !command.node().prefer_always_no_whitespace_before() && !is_at_newline_after_indented && (self.file_state.previous_node_requires_whitespace_after || command.node().prefer_whitespace_before()) {
            if let Some(char) = buffer.chars().last() {
                if char != ' ' {
                    buffer.push(' ');
                }
            }
        }

        // insert content
        let content = match command {
            Command::LeafCommand(leaf_command) => {
                let mut content = String::new();
                leaf_command.contents().iter().for_each(|c| content.push_str(c));
                content
            }
            Command::BranchCommand(branch_command) => {
                let mut child_flusher = Flusher::new(branch_command.children(), self.file_state, self.preferences);
                child_flusher.flush()
            }
        };
        buffer.push_str(content.as_str());

        // figure out new line state
        if let Some(index) = content.rfind("\n") {
            if index == content.len() - 1 {
                self.reset_state_to_newline();
            } else {
                self.file_state.line_remaining_length = content.len() - 1 - index;
            }
        } else {
            self.file_state.line_remaining_length -= content.len();
        }

        // open newline if last line exceed max line width
        if self.file_state.line_remaining_length <= 0 {
            buffer.push('\n');
            self.reset_state_to_newline();
        }

        // record whitespace state
        self.file_state.previous_node_requires_whitespace_after = command.node().prefer_whitespace_after();

        // going to the next command
        self.flusher_state.processing_index += 1;
    }
}