#[macro_export]
macro_rules! insert_punctuation {
    ($content:expr) => {
        {
            let punc = Punctuation::new($content, parse_span(&current), context.next_path());
            children.insert(punc.id(), punc.into());
        }
    };
}

#[macro_export]
macro_rules! parse_container_node_variables {
    () => {
        let span = parse_span(&pair);
        let mut children: std::collections::BTreeMap<usize, crate::ast::node::Node> = std::collections::BTreeMap::new();
        let path = context.next_parent_path();
    };
}

#[macro_export]
macro_rules! parse_node_variables {
    () => {
        let span = parse_span(&pair);
        let path = context.next_path();
    };
}

