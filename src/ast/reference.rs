#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ReferenceType {
    EnumDecorator,
    EnumMemberDecorator,
    ModelDecorator,
    ModelFieldDecorator,
    ModelRelationDecorator,
    ModelPropertyDecorator,
    InterfaceDecorator,
    InterfaceFieldDecorator,
    PipelineItem,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reference {
    path: Vec<usize>,
    r#type: ReferenceType,
}
