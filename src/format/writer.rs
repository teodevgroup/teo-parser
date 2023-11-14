use crate::format::Preferences;

pub struct Writer {
    pub preferences: Preferences,
    buffer: String,
    indent_level: usize,
}

impl Default for Writer {
    fn default() -> Self {
        Self {
            preferences: Preferences::default(),
            buffer: String::default(),
            indent_level: 0,
        }
    }
}

impl Writer {

    pub fn new(preferences: Preferences) -> Self {
        Self { preferences, buffer: String::new(), indent_level: 0 }
    }

    pub fn indent_level(&self) -> usize {
        self.indent_level
    }

    pub fn set_indent_level(&mut self, indent_level: usize) {
        if indent_level > 0 {
            self.indent_level = indent_level;
        }
    }

    pub fn increase_indent_level(&mut self) {
        self.indent_level += 1;
    }

    pub fn decrease_indent_level(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    pub fn write(&mut self, content: impl AsRef<str>) {
        self.buffer.push_str(content.as_ref());
    }

    pub fn output(&self) -> String {
        self.buffer.clone()
    }
}