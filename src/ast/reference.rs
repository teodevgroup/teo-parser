#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ReferenceType {
    EnumDecorator,
    EnumMemberDecorator,
    ModelDecorator,
    ModelFieldDecorator,
    ModelRelationDecorator,
    ModelPropertyDecorator,
    InterfaceDecorator,
    InterfaceFieldDecorator,
    HandlerDecorator,
    PipelineItem,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reference {
    pub(crate) path: Vec<usize>,
    pub(crate) r#type: ReferenceType,
}
