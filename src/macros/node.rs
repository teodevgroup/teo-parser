#[macro_export]
macro_rules! declare_node {
    ($struct_name:ident) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: crate::ast::span::Span,
            pub(crate) path: Vec<usize>,
        }
    };
    ($struct_name:ident, $($vis: vis $element: ident: $ty: ty),* $(,)?) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: crate::ast::span::Span,
            pub(crate) path: Vec<usize>,
            $($vis $element: $ty),*
        }
    };
}

#[macro_export]
macro_rules! declare_container_node {
    ($struct_name:ident) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: Span,
            pub(crate) path: Vec<usize>,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
        }
    };
    ($struct_name:ident, named) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: Span,
            pub(crate) path: Vec<usize>,
            pub(crate) string_path: Vec<String>,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
        }
    };
    ($struct_name:ident, availability) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: Span,
            pub(crate) path: Vec<usize>,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            pub(crate) define_availability: crate::availability::Availability,
            pub(crate) actual_availability: std::cell::RefCell<crate::availability::Availability>,
        }
    };
    ($struct_name:ident, named, availability, $($vis: vis $element: ident: $ty: ty),* $(,)?) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: crate::ast::span::Span,
            pub(crate) path: Vec<usize>,
            pub(crate) string_path: Vec<String>,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            pub(crate) define_availability: crate::availability::Availability,
            pub(crate) actual_availability: std::cell::RefCell<crate::availability::Availability>,
            $($vis $element: $ty),*
        }
    };
    ($struct_name:ident, named, $($vis: vis $element: ident: $ty: ty),* $(,)?) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: crate::ast::span::Span,
            pub(crate) path: Vec<usize>,
            pub(crate) string_path: Vec<String>,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            $($vis $element: $ty),*
        }
    };
    ($struct_name:ident, availability, $($vis: vis $element: ident: $ty: ty),* $(,)?) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: crate::ast::span::Span,
            pub(crate) path: Vec<usize>,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            pub(crate) define_availability: crate::availability::Availability,
            pub(crate) actual_availability: std::cell::RefCell<crate::availability::Availability>,
            $($vis $element: $ty),*
        }
    };
    ($struct_name:ident, $($vis: vis $element: ident: $ty: ty),* $(,)?) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub(crate) span: crate::ast::span::Span,
            pub(crate) children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            pub(crate) path: Vec<usize>,
            $($vis $element: $ty),*
        }
    };
}

#[macro_export]
macro_rules! impl_node_defaults {
    ($struct_name:ident) => {
        impl crate::traits::identifiable::Identifiable for $struct_name {
            fn path(&self) -> &Vec<usize> {
               &self.path
            }
        }
        impl crate::traits::node_trait::NodeTrait for $struct_name {
            fn span(&self) -> crate::ast::span::Span {
                self.span
            }
            fn children(&self) -> Option<&std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>> {
                None
            }
        }
        impl From<$struct_name> for crate::ast::node::Node {
            fn from(value: $struct_name) -> Self {
                crate::ast::node::Node::$struct_name(value)
            }
        }
        impl TryFrom<crate::ast::node::Node> for $struct_name {
            type Error = &'static str;
            fn try_from(value: crate::ast::node::Node) -> Result<Self, Self::Error> {
                match value {
                    crate::ast::node::Node::$struct_name(n) => Ok(n),
                    _ => Err("convert failed"),
                }
            }
        }
        impl std::fmt::Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.write_output_with_default_writer())
            }
        }
    };
}

#[macro_export]
macro_rules! impl_node_defaults_with_write {
    ($struct_name:ident, $display:ident) => {
        crate::impl_node_defaults!($struct_name);
        impl crate::traits::write::Write for $struct_name {
            fn write(&self, writer: &mut crate::format::Writer) {
                writer.write(&self.$display);
            }
        }
    };
    ($struct_name:ident, $display:expr) => {
        crate::impl_node_defaults!($struct_name);
        impl crate::traits::write::Write for $struct_name {
            fn write(&self, writer: &mut crate::format::Writer) {
                writer.write($display);
            }
        }
    };
}

#[macro_export]
macro_rules! impl_container_node_defaults {
    ($struct_name:ident) => {
        impl crate::traits::identifiable::Identifiable for $struct_name {
            fn path(&self) -> &Vec<usize> {
               &self.path
            }
        }
        impl crate::traits::node_trait::NodeTrait for $struct_name {
            fn span(&self) -> crate::ast::span::Span {
                self.span
            }
            fn children(&self) -> Option<&std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>> {
                Some(&self.children)
            }
        }
        impl From<$struct_name> for crate::ast::node::Node {
            fn from(value: $struct_name) -> Self {
                crate::ast::node::Node::$struct_name(value)
            }
        }
        impl TryFrom<crate::ast::node::Node> for $struct_name {
            type Error = &'static str;
            fn try_from(value: crate::ast::node::Node) -> Result<Self, Self::Error> {
                match value {
                    crate::ast::node::Node::$struct_name(n) => Ok(n),
                    _ => Err("convert failed"),
                }
            }
        }
    };
    ($struct_name:ident, named) => {
        impl crate::traits::identifiable::Identifiable for $struct_name {
            fn path(&self) -> &Vec<usize> {
               &self.path
            }
        }
        impl crate::traits::node_trait::NodeTrait for $struct_name {
            fn span(&self) -> crate::ast::span::Span {
                self.span
            }
            fn children(&self) -> Option<&std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>> {
                Some(&self.children)
            }
        }
        impl From<$struct_name> for crate::ast::node::Node {
            fn from(value: $struct_name) -> Self {
                crate::ast::node::Node::$struct_name(value)
            }
        }
        impl TryFrom<crate::ast::node::Node> for $struct_name {
            type Error = &'static str;
            fn try_from(value: crate::ast::node::Node) -> Result<Self, Self::Error> {
                match value {
                    crate::ast::node::Node::$struct_name(n) => Ok(n),
                    _ => Err("convert failed"),
                }
            }
        }
        impl crate::traits::named_identifiable::NamedIdentifiable for $struct_name {
            fn string_path(&self) -> &Vec<String> {
                &self.string_path
            }
        }
    };
    ($struct_name:ident, availability) => {
        impl crate::traits::identifiable::Identifiable for $struct_name {
            fn path(&self) -> &Vec<usize> {
               &self.path
            }
        }
        impl crate::traits::node_trait::NodeTrait for $struct_name {
            fn span(&self) -> crate::ast::span::Span {
                self.span
            }
            fn children(&self) -> Option<&std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>> {
                Some(&self.children)
            }
        }
        impl From<$struct_name> for crate::ast::node::Node {
            fn from(value: $struct_name) -> Self {
                crate::ast::node::Node::$struct_name(value)
            }
        }
        impl TryFrom<crate::ast::node::Node> for $struct_name {
            type Error = &'static str;
            fn try_from(value: crate::ast::node::Node) -> Result<Self, Self::Error> {
                match value {
                    crate::ast::node::Node::$struct_name(n) => Ok(n),
                    _ => Err("convert failed"),
                }
            }
        }
        impl crate::traits::has_availability::HasAvailability for $struct_name {
            fn define_availability(&self) -> crate::availability::Availability {
                self.define_availability
            }
            fn actual_availability(&self) -> crate::availability::Availability {
                *self.actual_availability.borrow()
            }
        }
    };
    ($struct_name:ident, named, availability) => {
        impl crate::traits::identifiable::Identifiable for $struct_name {
            fn path(&self) -> &Vec<usize> {
               &self.path
            }
        }
        impl crate::traits::node_trait::NodeTrait for $struct_name {
            fn span(&self) -> crate::ast::span::Span {
                self.span
            }
            fn children(&self) -> Option<&std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>> {
                Some(&self.children)
            }
        }
        impl From<$struct_name> for crate::ast::node::Node {
            fn from(value: $struct_name) -> Self {
                crate::ast::node::Node::$struct_name(value)
            }
        }
        impl TryFrom<crate::ast::node::Node> for $struct_name {
            type Error = &'static str;
            fn try_from(value: crate::ast::node::Node) -> Result<Self, Self::Error> {
                match value {
                    crate::ast::node::Node::$struct_name(n) => Ok(n),
                    _ => Err("convert failed"),
                }
            }
        }
        impl crate::traits::named_identifiable::NamedIdentifiable for $struct_name {
            fn string_path(&self) -> &Vec<String> {
                &self.string_path
            }
        }
        impl crate::traits::has_availability::HasAvailability for $struct_name {
            fn define_availability(&self) -> crate::availability::Availability {
                self.define_availability
            }
            fn actual_availability(&self) -> crate::availability::Availability {
                *self.actual_availability.borrow()
            }
        }
    };
}

#[macro_export]
macro_rules! impl_container_node_defaults_with_display {
    ($struct_name:ident) => {
        crate::impl_container_node_defaults!($struct_name);
        impl std::fmt::Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for child in self.children.values() {
                    std::fmt::Display::fmt(child, f)?;
                }
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! node_children_iter {
    ($struct_name:ident, $child_struct_name:ident, $iter_name:ident, $field_name:ident) => {
        pub struct $iter_name<'a> {
            index: usize,
            owner: &'a $struct_name,
        }
        impl<'a> Iterator for $iter_name<'a> {
            type Item = &'a $child_struct_name;
            fn next(&mut self) -> Option<Self::Item> {
                self.index += 1;
                self.owner.$field_name.get(self.index - 1).map(|i| self.owner.children.get(i).unwrap().try_into().unwrap())
            }
        }
    };
}

#[macro_export]
macro_rules! node_children_iter_fn {
    ($fn_name:ident, $iter_name:ident) => {
        pub fn $fn_name(&self) -> $iter_name {
            $iter_name {
                owner: self,
                index: 0,
            }
        }
    }
}

#[macro_export]
macro_rules! node_children_pair_iter {
    ($struct_name:ident, $child_struct_name:ident, $iter_name:ident, $field_name:ident) => {
        pub struct $iter_name<'a> {
            index: usize,
            owner: &'a $struct_name,
        }
        impl<'a> Iterator for $iter_name<'a> {
            type Item = (&'a $child_struct_name, &'a $child_struct_name);
            fn next(&mut self) -> Option<Self::Item> {
                self.index += 1;
                self.owner.$field_name.get(self.index - 1).map(|(k, v)| (self.owner.children.get(k).unwrap().try_into().unwrap(), self.owner.children.get(v).unwrap().try_into().unwrap()))
            }
        }
    };
}

#[macro_export]
macro_rules! node_child_fn {
    ($name:ident, $struct_type:ident) => {
        pub fn $name(&self) -> &$struct_type {
            self.children.get(&self.$name).unwrap().try_into().unwrap()
        }
    }
}

#[macro_export]
macro_rules! node_optional_child_fn {
    ($name:ident, $class:ident) => {
        pub fn $name(&self) -> Option<&$class> {
            self.$name.map(|n| self.children.get(&n).unwrap().try_into()).flatten()
        }
    }
}
