use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(CodeComment, lines: Vec<String>);

impl_node_defaults!(CodeComment);

impl CodeComment {

    pub fn lines(&self) -> &Vec<String> {
        &self.lines
    }
}

impl Write for CodeComment {
    fn write(&self, writer: &mut Writer) {
        let mut contents = vec![];
        for line in self.lines() {
            contents.push("// ");
            contents.push(line.as_str());
            contents.push("\n");
        }
        writer.write_contents(self, contents);
    }
}
