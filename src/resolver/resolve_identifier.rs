use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::reference::{Reference, ReferenceType};
use crate::ast::top::Top;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_identifier(
    identifier: &Identifier,
    context: &mut ResolverContext,
    reference_type: ReferenceType,
) -> Option<Reference> {

}

pub(super) fn resolve_identifier_path(
    identifier_path: &IdentifierPath,
    context: &mut ResolverContext,
    reference_type: ReferenceType,
) -> Option<Reference> {
    context.current_namespace()
}

fn top_filter_for_reference_type(reference_type: ReferenceType) -> fn(&Top) -> bool {
    match reference_type {
        ReferenceType::EnumDecorator |
        ReferenceType::EnumMemberDecorator |
        ReferenceType::ModelDecorator |
        ReferenceType::ModelFieldDecorator |
        ReferenceType::ModelRelationDecorator |
        ReferenceType::ModelPropertyDecorator |
        ReferenceType::InterfaceDecorator |
        ReferenceType::InterfaceFieldDecorator => |top: &Top| {
            top.as_decorator_declaration().map_or(false, |d| d.decorator_class == reference_type)
        },
        ReferenceType::PipelineItem => |top: &Top| {
            top.as_pipeline_item_declaration().is_some()
        },
        ReferenceType::Default => |top: &Top| {
            top.is_enum() || top.is_model() || top.is_interface() || top.is_config() || top.is_constant()
        }
    }
}