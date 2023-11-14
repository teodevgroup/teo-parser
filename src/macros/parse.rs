#[macro_export]
macro_rules! parse_insert_punctuation {
    ($context:ident, $current:ident, $children:ident, $content:expr) => {
        {
            let punc = crate::ast::punctuations::Punctuation::new($content, parse_span(&$current), $context.next_path());
            $children.insert(punc.id(), punc.into());
        }
    };
}

#[macro_export]
macro_rules! parse_insert_keyword {
    ($context:ident, $current:ident, $children:ident, $content:expr) => {
        {
            let keyword = crate::ast::keyword::Keyword::new($content, parse_span(&$current), $context.next_path());
            $children.insert(keyword.id(), keyword.into());
        }
    };
}

#[macro_export]
macro_rules! parse_append {
    ($expr:expr, $children:ident) => {
        {
            let node = $expr;
            $children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_insert {
    ($expr:expr, $children:ident, $dest:ident) => {
        {
            let node = $expr;
            $dest.push(node.id());
            $children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_set {
    ($expr:expr, $children:ident, $dest:ident) => {
        {
            let node = $expr;
            $dest = node.id();
            $children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_set_optional {
    ($expr:expr, $children:ident, $dest:ident) => {
        {
            let node = $expr;
            $dest = Some(node.id());
            $children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_set_identifier_and_string_path {
    ($context: ident, $current: ident, $children: ident, $identifier: ident, $string_path: ident) => {
        {
            let node = crate::parser::parse_identifier::parse_identifier(&$current, $context);
            $identifier = node.id();
            $string_path = Some($context.next_parent_string_path(node.name()));
            $children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_container_node_variables {
    ($pair:ident, $context:ident) => {
        {
            let span = parse_span(&$pair);
            let children: std::collections::BTreeMap<usize, crate::ast::node::Node> = std::collections::BTreeMap::new();
            let path = $context.next_parent_path();
            (span, path, children)
        }
    };
    ($pair:ident, $context:ident, named) => {
        {
            let span = parse_span(&$pair);
            let children: std::collections::BTreeMap<usize, crate::ast::node::Node> = std::collections::BTreeMap::new();
            let path = $context.next_parent_path();
            let string_path: Vec<String> = Vec::new();
            (span, path, string_path, children)
        }
    };
    ($pair:ident, $context:ident, availability) => {
        {
            let span = parse_span(&$pair);
            let children: std::collections::BTreeMap<usize, crate::ast::node::Node> = std::collections::BTreeMap::new();
            let path = $context.next_parent_path();
            let define_availability = $context.current_availability_flag();
            let actual_availability = std::cell::RefCell::new(crate::availability::Availability::none());
            (span, path, children, define_availability, actual_availability)
        }
    };
    ($pair:ident, $context:ident, named, availability) => {
        {
            let span = parse_span(&$pair);
            let children: std::collections::BTreeMap<usize, crate::ast::node::Node> = std::collections::BTreeMap::new();
            let path = $context.next_parent_path();
            let string_path: Vec<String> = Vec::new();
            let define_availability = $context.current_availability_flag();
            let actual_availability = std::cell::RefCell::new(crate::availability::Availability::none());
            (span, path, string_path, children, define_availability, actual_availability)
        }
    };
}

#[macro_export]
macro_rules! parse_container_node_variables_cleanup {
    ($context: ident) => {
        $context.pop_parent_id();
    };
    ($context: ident, named) => {
        $context.pop_parent_id();
        $context.pop_string_path();
    }
}

#[macro_export]
macro_rules! parse_node_variables {
    ($pair:ident, $context:ident) => {
        {
            let span = parse_span(&$pair);
            let path = $context.next_path();
            (span, path)
        }
    };
}
