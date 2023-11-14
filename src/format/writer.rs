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

impl Default for Writer<'_> {
    fn default() -> Self {
        Self::new(Preferences::default())
    }
}

impl<'a> Writer<'a> {

    pub fn new(preferences: Preferences) -> Self {
        Self {
            preferences,
            commands: vec![],
        }
    }

    pub fn write_children(&'a mut self, node: &'a dyn Write, children: Values<usize, Node>) {
        let mut writer = Self::new(self.preferences);
        children.for_each(|c| c.write(&mut writer));
        self.commands.push(Command::branch(node, writer.commands));
    }

    pub fn write_content(&'a mut self, node: &'a dyn Write, content: &'a str) {
        self.commands.push(Command::leaf(node, vec![content.as_ref()]));
    }

    pub fn write_contents(&mut self, node: &dyn Write, contents: Vec<&'a str>) {
        self.commands.push(Command::leaf(node, contents));
    }

    pub fn flush(&self) -> String {
        let mut flusher = Flusher::new_from_beginning(&self.commands, self.preferences);
        flusher.flush()
    }
}