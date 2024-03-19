use std::fmt::{Display, Formatter};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct File {
    pub filepath: String,
    #[serde(rename(serialize = "contentType"))]
    pub content_type: Option<String>,
    pub filename: String,
    #[serde(rename(serialize = "filenameExt"))]
    pub filename_ext: Option<String>,
}

impl Display for File {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("File(\"")?;
        f.write_str(&self.filepath.as_str().replace("\"", "\\\""))?;
        f.write_str("\")")
    }
}