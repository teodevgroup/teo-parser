#[macro_export]
macro_rules! declare_node {
    ($struct_name:ident) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub span: Span,
            pub path: Vec<usize>,
        }
    };
    ($struct_name:ident, $($element: ident: $ty: ty),*) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub span: crate::ast::span::Span,
            pub path: Vec<usize>,
            pub $($element: $ty),*
        }
    }
}

#[macro_export]
macro_rules! declare_container_node {
    ($struct_name:ident) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub span: Span,
            pub children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            pub path: Vec<usize>,
        }
    };
    ($struct_name:ident, $($element: ident: $ty: ty),*) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub span: crate::ast::span::Span,
            pub children: std::collections::btree_map::BTreeMap<usize, crate::ast::node::Node>,
            pub path: Vec<usize>,
            pub $($element: $ty),*
        }
    }
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
    };
}

#[macro_export]
macro_rules! impl_node_defaults_with_display {
    ($struct_name:ident, $display_from:ident) => {
        crate::impl_node_defaults!($struct_name);
        impl std::fmt::Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.$display_from())
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
    ($struct_name:ident, $child_struct_name:ident, $iter_name:ident, $field_name:ident, $as_expression:ident) => {
        pub struct $iter_name<'a> {
            index: usize,
            owner: &'a $struct_name,
        }

        impl<'a> Iterator for $iter_name<'a> {

            type Item = &'a $child_struct_name;

            fn next(&mut self) -> Option<Self::Item> {
                self.index += 1;
                self.owner.$field_name.get(self.index - 1).map(|i| self.owner.children.get(i).unwrap().$as_expression().unwrap())
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
macro_rules! node_child_fn {
    ($name:ident, $struct_type:ident, $as_expression:ident) => {
        pub fn $name(&self) -> &$struct_type {
            self.children.get(&self.$name).unwrap().$as_expression().unwrap()
        }
    }
}

#[macro_export]
macro_rules! node_optional_child_fn {
    ($name:ident, $class:ident, $as_expression:ident) => {
        pub fn $name(&self) -> Option<&$class> {
            self.$name.map(|n| self.children.get(&n).unwrap().$as_expression()).flatten()
        }
    }
}
