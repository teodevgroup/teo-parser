use crate::ast::literals::StringLiteral;
use crate::ast::span::Span;
use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(Import,
    pub source: StringLiteral,
    pub file_path: String,
);

impl_node_defaults!(Import);

impl Import {

    pub fn new(path: Vec<usize>, source: StringLiteral, file_path: String, span: Span) -> Self {
        Self {
            path,
            source,
            file_path,
            span,
        }
    }
}

impl Write for Import {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_contents(self, vec!["import ", self.source.display.as_str()])
    }

    fn always_start_on_new_line(&self) -> bool {
        true
    }

    fn always_end_on_new_line(&self) -> bool {
        true
    }
}