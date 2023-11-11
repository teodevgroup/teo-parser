pub trait NamedIdentifiable {

    fn string_path(&self) -> &Vec<String>;

    fn str_path(&self) -> Vec<&str> {
        self.string_path().iter().map(AsRef::as_ref).collect()
    }

    fn name(&self) -> &str {
        *self.str_path().last().unwrap()
    }
}

