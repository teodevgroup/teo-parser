pub mod item;

use std::fmt::{Display, Formatter};
pub use item::Item;

#[derive(Debug, PartialEq, Clone)]
pub struct Pipeline {
    pub items: Vec<Item>
}

impl Pipeline {
    pub fn new(items: Vec<Item>) -> Self {
        Self { items }
    }
}

impl Display for Pipeline {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (index, item) in self.items.iter().enumerate() {
            if index == 0 {
                f.write_str("$")?;
                Display::fmt(item, f)?;
            } else {
                f.write_str(".")?;
                Display::fmt(item, f)?;
            }
        }
        Ok(())
    }
}