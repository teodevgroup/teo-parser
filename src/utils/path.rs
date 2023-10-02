use std::fs;
use std::path::{Path, PathBuf};
use path_clean::PathClean;

pub struct FileUtility {
    pub read_file: fn(file_path: &str) -> Option<String>,
    pub file_exists: fn(file_path: &str) -> bool,
    pub path_join: fn(base: &str, path: &str) -> String,
    pub parent_directory: fn(file_path: &str) -> String,
    pub path_is_absolute: fn(file_path: &str) -> bool,
}

impl FileUtility {

    pub fn import_path(&self, source_path: &str, string: &str) -> String {
        (self.path_join)(&(self.parent_directory)(source_path), string)
    }
}

impl Default for FileUtility {

    fn default() -> Self {
        Self {
            read_file,
            file_exists,
            path_join,
            parent_directory,
            path_is_absolute,
        }
    }
}

fn read_file(file_path: &str) -> Option<String> {
    match fs::read_to_string(Path::new(file_path)) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

fn file_exists(file_path: &str) -> bool {
    Path::new(file_path).exists()
}

fn parent_directory(path: &str) -> String {
    let mut path = PathBuf::from(path);
    path.pop();
    path.to_str().unwrap().to_string()
}

fn path_is_absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
}

fn path_join(base: &str, path: &str) -> String {
    Path::new(base).join(Path::new(path)).clean().to_str().unwrap().to_string()
}