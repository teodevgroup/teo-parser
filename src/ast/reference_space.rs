#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReferenceSpace {
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
    Middleware,
    Default,
}
