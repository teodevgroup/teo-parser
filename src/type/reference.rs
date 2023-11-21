use serde::Serialize;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize)]
pub struct Reference {
    path: Vec<usize>,
    string_path: Vec<String>,
}

impl Reference {

    pub fn new(path: Vec<usize>, string_path: Vec<String>) -> Self {
        Self { path, string_path, }
    }

    pub fn path(&self) -> &Vec<usize> {
        &self.path
    }

    pub fn path_without_last(&self, n: usize) -> Vec<usize> {
        self.path().iter().rev().skip(n).rev().map(Clone::clone).collect()
    }

    pub fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }

    pub fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }

    pub fn str_path_without_last(&self, n: usize) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).rev().skip(n).rev().collect()
    }
}