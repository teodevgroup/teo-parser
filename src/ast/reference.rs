#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ReferenceType {
    /// Resolve the reference with the field decorator map
    FieldDecorator,
    /// Resolve the reference with the relation decorator map
    RelationDecorator,
    /// Resolve the reference with the property decorator map
    PropertyDecorator,
    /// Resolve the reference with the model decorator map
    ModelDecorator,
    /// Resolve the reference with the pipeline item map
    PipelineItem,
    /// Resolve the reference with the default map
    Default,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Reference {
    path: Vec<String>,
}
