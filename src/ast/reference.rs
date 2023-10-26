#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReferenceType {
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
