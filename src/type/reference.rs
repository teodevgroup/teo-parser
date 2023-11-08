#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reference {
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
}

impl Reference {

    pub fn new(path: Vec<usize>, string_path: Vec<String>) -> Self {
        Self { path, string_path, }
    }
}