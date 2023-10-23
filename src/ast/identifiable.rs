pub trait Identifiable {

    fn source_id(&self) -> usize;

    fn id(&self) -> usize;

    fn path(&self) -> &Vec<usize>;

    fn str_path(&self) -> Vec<&str>;
}