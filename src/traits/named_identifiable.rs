pub trait NamedIdentifiable {

    fn string_path(&self) -> &Vec<String>;

    fn str_path(&self) -> Vec<&str> {
        self.string_path().iter().map(AsRef::as_ref).collect()
    }

    fn name(&self) -> &str {
        *self.str_path().last().unwrap()
    }

    fn parent_string_path(&self) -> Vec<String> {
        let mut result = self.string_path().clone();
        result.pop();
        result
    }
}

