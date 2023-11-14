use crate::format::command::Command;
use crate::format::Preferences;
use crate::format::state::State;
use crate::traits::write::Write;

pub struct Writer<'a> {
    pub preferences: Preferences,
    commands: Vec<Command<'a>>,
    state: State,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new(Preferences::default())
    }
}

impl Writer {

    pub fn new(preferences: Preferences) -> Self {
        let line_remaining_length = preferences.maximum_line_width();
        Self {
            preferences,
            commands: vec![],
            state: {
                let mut state = State::default();
                state.line_remaining_length = line_remaining_length;
                state
            },
        }
    }

    pub fn write(&mut self, node: &dyn Write, content: impl AsRef<str>) {
        self.commands.push(Command::new(node, content.as_ref()));
    }

    pub fn flush(&mut self) -> String {
        let mut buffer = "".to_owned();
        loop {
            if self.is_finished() { break }
            self.write_next_command(&mut buffer);
        }
        buffer
    }

    fn is_finished(&self) -> bool {
        self.state.processing_index >= self.commands.len()
    }

    fn write_next_command(&mut self, buffer: &mut String) {
        let command = self.commands.get(self.state.processing_index).unwrap();
        if command.node().is_block_start() {
            self.write_block(buffer);
        } else {
            self.write_non_block_command(buffer);
        }
    }

    fn reset_state_to_newline(&mut self) {
        self.state.is_at_newline = true;
        self.state.line_remaining_length = self.preferences.maximum_line_width();
    }

    fn write_block(&mut self, buffer: &mut String) {

        // retrieve command
        let command = self.commands.get(self.state.processing_index).unwrap();

        // figure out can we write in one line
        let mut index = self.state.processing_index + 1;
        let mut block_level = 0;
        let mut captured_line_remaining_length = self.state.line_remaining_length;
        loop {
            if index >= self.commands.len() { break }
            let command = self.commands.get(index).unwrap();

            index += 1;
        }
    }

    fn write_non_block_command(&mut self, buffer: &mut String) {

        // retrieve command
        let command = self.commands.get(self.state.processing_index).unwrap();

        // capture newline status
        let is_at_newline_after_indented = self.state.is_at_newline;

        // insert indentations if needed
        if self.state.is_at_newline {
            if self.state.indent_level != 0 {
                let whitespace_count = self.state.indent_level * self.preferences.indent_size();
                self.state.line_remaining_length -= whitespace_count;
                buffer.push_str(&" ".repeat(whitespace_count));
            }
            self.state.is_at_newline = false;
        }

        // insert leading whitespace if needed
        if !command.node().prefer_always_no_whitespace_before() && !is_at_newline_after_indented && (self.state.previous_node_requires_whitespace_after || command.node().prefer_whitespace_before()) {
            buffer.push(' ');
        }

        // insert content
        buffer.push_str(command.content());

        // figure out new line state
        if let Some(index) = command.content().rfind("\n") {
            if index == command.content().len() - 1 {
                self.reset_state_to_newline();
            } else {
                self.state.line_remaining_length = command.content().len() - 1 - index;
            }
        } else {
            self.state.line_remaining_length -= command.content().len();
        }

        // open newline if last line exceed max line width
        if self.state.line_remaining_length <= 0 {
            buffer.push('\n');
            self.reset_state_to_newline();
        }

        // record whitespace state
        self.state.previous_node_requires_whitespace_after = command.node().prefer_whitespace_after();

        // going to the next command
        self.state.processing_index += 1;
    }
}