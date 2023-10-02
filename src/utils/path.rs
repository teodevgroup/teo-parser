use regex::Regex;

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