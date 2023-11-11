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
            pub children: Vec<Node>,
            pub path: Vec<usize>,
        }
    };
    ($struct_name:ident, $($element: ident: $ty: ty),*) => {
        #[derive(Debug)]
        pub struct $struct_name {
            pub span: crate::ast::span::Span,
            pub children: Vec<Node>,
            pub path: Vec<usize>,
            pub $($element: $ty),*
        }
    }
}

#[macro_export]
macro_rules! impl_node_defaults {
    ($struct_name:ident, $display_from:ident) => {
        impl crate::traits::identifiable::Identifiable for $struct_name {
            fn path(&self) -> &Vec<usize> {
               &self.path
            }
        }
        impl crate::traits::node_trait::NodeTrait for $struct_name {
            fn span(&self) -> crate::ast::span::Span {
                self.span
            }
            fn children(&self) -> Option<&Vec<crate::ast::node::Node>> {
                None
            }
        }
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
            fn children(&self) -> Option<&Vec<crate::ast::node::Node>> {
                Some(&self.children)
            }
        }
    };
}