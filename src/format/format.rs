use crate::ast::schema::Schema;
use crate::traits::write::Write;

pub fn format_document(schema: &Schema, file_path: &str) -> String {
    if let Some(source) = schema.source_at_path(file_path) {
        source.write_output_with_default_writer()
    } else {
        "".to_owned()
    }
}