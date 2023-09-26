use std::path::{Path, PathBuf};
use path_clean::PathClean;

pub(crate) fn import_path(source_path: &Path, string: &str) -> PathBuf {
    let mut dir = source_path.to_owned();
    dir.pop(); // get the parent path of the source file
    dir.join(string).clean()
}