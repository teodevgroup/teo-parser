use array_tool::vec::Join;

pub(crate) fn readable_namespace_path(path: &Vec<String>) -> String {
    if path.len() <= 1 {
        return "main".to_owned()
    }
    let mut path = path.clone();
    path.pop();
    if path.len() == 0 {
        return "main".to_owned()
    } else {
        path.join(".")
    }
}