use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults};

declare_node!(Punctuation, content: String);

impl Punctuation {

    pub fn content(&self) -> &str {
        self.content.as_str()
    }
}

impl_node_defaults!(Punctuation);

impl Display for Punctuation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.content() {
            ":" => ": ",
            _ => self.content(),
        })
    }
}
