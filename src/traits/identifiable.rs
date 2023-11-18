pub trait Identifiable {

    fn path(&self) -> &Vec<usize>;

    fn source_id(&self) -> usize {
        *self.path().first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path().last().unwrap()
    }

    fn parent_path(&self) -> Vec<usize> {
        let mut result = self.path().clone();
        result.pop();
        result
    }
}