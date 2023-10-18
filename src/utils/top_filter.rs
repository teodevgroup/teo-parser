use std::sync::Arc;
use crate::ast::reference::ReferenceType;
use crate::ast::top::Top;

pub(crate) fn top_filter_for_reference_type(reference_type: ReferenceType) -> Arc<dyn Fn(&Top) -> bool> {
    match reference_type {
        ReferenceType::EnumDecorator |
        ReferenceType::EnumMemberDecorator |
        ReferenceType::ModelDecorator |
        ReferenceType::ModelFieldDecorator |
        ReferenceType::ModelRelationDecorator |
        ReferenceType::ModelPropertyDecorator |
        ReferenceType::InterfaceDecorator |
        ReferenceType::InterfaceFieldDecorator |
        ReferenceType::HandlerDecorator => Arc::new(move |top: &Top| {
            top.as_decorator_declaration().map_or(false, |d| d.decorator_class == reference_type)
        }),
        ReferenceType::PipelineItem => Arc::new(|top: &Top| {
            top.as_pipeline_item_declaration().is_some()
        }),
        ReferenceType::Default => Arc::new(|top: &Top| {
            top.is_enum() || top.is_model() || top.is_interface_declaration() || top.is_struct_declaration() || top.is_config() || top.is_constant() || top.is_namespace()
        }),
    }
}

pub(crate) fn top_filter_for_any_model_field_decorators() -> Arc<dyn Fn(&Top) -> bool> {
    Arc::new(|top: &Top| {
        top.as_decorator_declaration().map_or(false, |d| match d.decorator_class {
            ReferenceType::ModelFieldDecorator => true,
            ReferenceType::ModelRelationDecorator => true,
            ReferenceType::ModelPropertyDecorator => true,
            _ => false,
        })
    })
}

pub(crate) fn top_filter_for_pipeline() -> Arc<dyn Fn(&Top) -> bool> {
    Arc::new(|top: &Top| {
        top.is_pipeline_item_declaration() || top.is_namespace()
    })
}