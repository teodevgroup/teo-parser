pub mod item;

pub use item::Item;

#[derive(Debug, Eq, PartialEq)]
pub struct Pipeline {
    pub items: Vec<Item>
}

impl Pipeline {
    pub fn new(items: Vec<Item>) -> Self {
        Self { items }
    }
}