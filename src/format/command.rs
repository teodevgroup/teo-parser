use crate::traits::write::Write;

pub(super) enum Command<'a> {
    BranchCommand(BranchCommand<'a>),
    LeafCommand(LeafCommand<'a>),
}

pub(super) struct BranchCommand<'a> {
    node: &'a dyn Write,
    children: Vec<Command<'a>>,
}

pub(super) struct LeafCommand<'a> {
    node: &'a dyn Write,
    contents: Vec<&'a str>,
}

impl<'a> Command<'a> {

    pub(super) fn leaf(node: &'a dyn Write, contents: Vec<&'a str>) -> Self {
        Self::LeafCommand(LeafCommand { node, contents })
    }

    pub(super) fn branch(node: &'a dyn Write, children: Vec<Command<'a>>) -> Self {
        Self::BranchCommand(BranchCommand { node, children })
    }

    pub(super) fn is_leaf_command(&'a self) -> bool {
        self.as_leaf_command().is_some()
    }

    pub(super) fn as_leaf_command(&'a self) -> Option<&'a LeafCommand<'a>> {
        match self {
            Command::LeafCommand(c) => Some(c),
            _ => None,
        }
    }

    pub(super) fn is_branch_command(&'a self) -> bool {
        self.as_branch_command().is_some()
    }

    pub(super) fn as_branch_command(&'a self) -> Option<&'a BranchCommand<'a>> {
        match self {
            Command::BranchCommand(c) => Some(c),
            _ => None,
        }
    }

    pub(super) fn node(&'a self) -> &'a dyn Write {
        match self {
            Command::BranchCommand(c) => c.node,
            Command::LeafCommand(c) => c.node,
        }
    }
}

impl<'a> BranchCommand<'a> {

    pub(super) fn children(&'a self) -> &'a Vec<Command> {
        &self.children
    }
}

impl<'a> LeafCommand<'a> {

    pub(super) fn contents(&'a self) -> &'a Vec<&'a str> {
        &self.contents
    }
}