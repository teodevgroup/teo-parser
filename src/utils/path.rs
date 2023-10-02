use std::fs;
use std::path::Path;
use regex::Regex;

pub struct FileUtility {
    pub read_file: fn(file_path: &str) -> Option<String>,
    pub file_exists: fn(file_path: &str) -> bool,
}

impl Default for FileUtility {

    fn default() -> Self {
        Self {
            read_file,
            file_exists,
        }
    }
}

pub(crate) fn read_file(file_path: &str) -> Option<String> {
    match fs::read_to_string(Path::new(file_path)) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

pub(crate) fn file_exists(file_path: &str) -> bool {
    Path::new(file_path).exists()
}

pub(crate) fn import_path(source_path: &str, string: &str) -> String {
    join_path(&parent_directory(source_path), string)
}

pub(crate) fn parent_directory(path: &str) -> String {
    if path.starts_with("/") {
        let mut parts: Vec<&str> = path.split("/").into_iter().collect();
        parts.remove(parts.len() - 1);
        parts.join("/")
    } else {
        let mut parts: Vec<&str> = path.split("\\").into_iter().collect();
        parts.remove(parts.len() - 1);
        parts.join("\\")
    }
}

pub(crate) fn is_absolute(path: &str) -> bool {
    if path.starts_with("/") {
        return true;
    }
    let regex = Regex::new("^\\w:\\\\").unwrap();
    if regex.is_match(path) {
        return true;
    }
    false
}

pub(crate) fn join_path(base: &str, path: &str) -> String {
    if base.contains("/") {
        format!("{}/{}", base, path)
    } else {
        format!("{}\\{}", base, path)
    }
}