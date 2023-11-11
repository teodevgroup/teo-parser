use crate::{declare_node, impl_node_defaults};

declare_node!(Punctuation, content: String);

impl Punctuation {

    pub fn content(&self) -> &str {
        self.content.as_str()
    }
}

impl_node_defaults!(Punctuation, content);
