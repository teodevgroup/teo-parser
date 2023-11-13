#[macro_export]
macro_rules! parse_insert_punctuation {
    ($content:expr) => {
        {
            let punc = Punctuation::new($content, parse_span(&current), context.next_path());
            children.insert(punc.id(), punc.into());
        }
    };
}

#[macro_export]
macro_rules! parse_append {
    ($expr:expr) => {
        {
            let node = $expr;
            children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_insert {
    ($expr:expr, $dest:ident) => {
        {
            let node = $expr;
            $dest.push(node.id());
            children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_set {
    ($expr:expr, $dest:ident) => {
        {
            let node = $expr;
            $dest = node.id();
            children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_set_optional {
    ($expr:expr, $dest:ident) => {
        {
            let node = $expr;
            $dest = Some(node.id());
            children.insert(node.id(), node.into());
        }
    };
}

#[macro_export]
macro_rules! parse_set_identifier_and_string_path {
    () => {
        {
            let node = parse_identifier(&current);
            identifier = node.id();
            string_path = Some(context.next_string_path(node.name()));
            children.insert(node.id(), node.into());
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
    (named) => {
        let span = parse_span(&pair);
        let mut children: std::collections::BTreeMap<usize, crate::ast::node::Node> = std::collections::BTreeMap::new();
        let path = context.next_parent_path();
        let mut string_path: Option<Vec<String>> = None;
    }
}

#[macro_export]
macro_rules! parse_container_node_variables_cleanup {
    () => {
        context.pop_parent_id();
    };
    (named) => {
        context.pop_parent_id();
        context.pop_string_path();
    }
}

#[macro_export]
macro_rules! parse_node_variables {
    () => {
        let span = parse_span(&pair);
        let path = context.next_path();
    };
}

#[macro_export]
macro_rules! parse_build_struct {
    ($struct_name:ident, $($element: ident: $expr: expr),* $(,)?) => {
        $struct_name {
            span,
            path,
            $($element: $ty),*
        }
    };
}

#[macro_export]
macro_rules! parse_build_container_struct {
    ($struct_name:ident, named, $($element: ident: $expr: expr),* $(,)?) => {
        $struct_name {
            span,
            path,
            children,
            string_path: string_path.unwrap(),
            $($element: $ty),*
        }
    };
    ($struct_name:ident, named, availability, $($element: ident: $expr: expr),* $(,)?) => {
        $struct_name {
            span,
            path,
            children,
            string_path: string_path.unwrap(),
            define_availability: context.current_availability_flag(),
            actual_availability: std::cell::RefCell::RefCell::new(crate::availability::Availability::none()),
            $($element: $expr),*
        }

    };
    ($struct_name:ident, availability, $($element: ident: $expr: expr),* $(,)?) => {
        $struct_name {
            span,
            path,
            children,
            define_availability: context.current_availability_flag(),
            actual_availability: std::cell::RefCell::RefCell::new(crate::availability::Availability::none()),
            $($element: $expr),*
        }
    };
    ($struct_name:ident, $($element: ident: $expr: expr),* $(,)?) => {
        $struct_name {
            span,
            path,
            children,
            $($element: $expr),*
        }
    };
}