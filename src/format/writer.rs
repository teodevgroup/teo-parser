use std::collections::btree_map::Values;
use crate::ast::node::Node;
use crate::format::command::Command;
use crate::format::flusher::Flusher;
use crate::format::Preferences;
use crate::traits::write::Write;

pub struct Writer<'a> {
    pub(super) preferences: Preferences,
    pub(super) commands: Vec<Command<'a>>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new(Preferences::default())
    }
}

impl Writer {

    pub fn new(preferences: Preferences) -> Self {
        Self {
            preferences,
            commands: vec![],
        }
    }

    pub fn write_children(&mut self, node: &dyn Write, children: Values<usize, Node>) {
        let mut writer = Self::new(self.preferences);
        children.for_each(|c| c.write(&mut writer));
        self.commands.push(Command::branch(node, writer.commands));
    }

    pub fn write_content(&mut self, node: &dyn Write, content: impl AsRef<str>) {
        self.commands.push(Command::leaf(node, content.as_ref()));
    }

    pub fn flush(&self) -> String {
        let mut flusher = Flusher::new(self);
        flusher.flush()
    }
}