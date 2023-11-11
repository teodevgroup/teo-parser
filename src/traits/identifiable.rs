pub trait Identifiable {

    fn path(&self) -> &Vec<usize>;

    fn source_id(&self) -> usize {
        *self.path().first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path().last().unwrap()
    }
}