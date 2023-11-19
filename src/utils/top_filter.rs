use std::sync::Arc;
use crate::ast::node::Node;
use crate::ast::r#enum::Enum;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::struct_declaration::StructDeclaration;
use crate::completion::find_completion_in_type_expr::TypeExprFilter;
use crate::traits::named_identifiable::NamedIdentifiable;

pub fn top_filter_for_reference_type(reference_type: ReferenceSpace) -> Arc<dyn Fn(&Node) -> bool> {
    match reference_type {
        ReferenceSpace::EnumDecorator |
        ReferenceSpace::EnumMemberDecorator |
        ReferenceSpace::ModelDecorator |
        ReferenceSpace::ModelFieldDecorator |
        ReferenceSpace::ModelRelationDecorator |
        ReferenceSpace::ModelPropertyDecorator |
        ReferenceSpace::InterfaceDecorator |
        ReferenceSpace::InterfaceFieldDecorator |
        ReferenceSpace::HandlerDecorator => Arc::new(move |top: &Node| {
            top.as_decorator_declaration().map_or(false, |d| d.decorator_class == reference_type)
        }),
        ReferenceSpace::PipelineItem => Arc::new(|top: &Node| {
            top.as_pipeline_item_declaration().is_some()
        }),
        ReferenceSpace::Middleware => Arc::new(|top: &Node| {
            top.as_middleware_declaration().is_some()
        }),
        ReferenceSpace::Default => Arc::new(|top: &Node| {
            top.is_enum() || top.is_model() || top.is_interface_declaration() || top.is_struct_declaration() || top.is_config() || top.is_constant_declaration() || top.is_namespace()
        }),
    }
}

pub fn top_filter_for_any_model_field_decorators() -> Arc<dyn Fn(&Node) -> bool> {
    Arc::new(|top: &Node| {
        top.as_decorator_declaration().map_or(false, |d| match d.decorator_class {
            ReferenceSpace::ModelFieldDecorator => true,
            ReferenceSpace::ModelRelationDecorator => true,
            ReferenceSpace::ModelPropertyDecorator => true,
            _ => false,
        })
    })
}

pub fn top_filter_for_pipeline() -> Arc<dyn Fn(&Node) -> bool> {
    Arc::new(|top: &Node| {
        top.is_pipeline_item_declaration() || top.is_namespace()
    })
}

pub fn top_filter_for_middleware() -> Arc<dyn Fn(&Node) -> bool> {
    Arc::new(|top: &Node| {
        top.is_middleware_declaration() || top.is_namespace()
    })
}

pub fn top_filter_for_model() -> Arc<dyn Fn(&Node) -> bool> {
    Arc::new(|top: &Node| {
        top.is_model()
    })
}

pub fn top_filter_for_type_expr_filter(type_expr_filter: TypeExprFilter) -> Arc<dyn Fn(&Node) -> bool> {
    match type_expr_filter {
        TypeExprFilter::None => Arc::new(|top: &Node| {
            top.is_model() || top.is_interface_declaration() || top.is_enum() || (top.is_struct_declaration() && !struct_is_builtin(top.as_struct_declaration().unwrap()))
        }),
        TypeExprFilter::Model => Arc::new(|top: &Node| {
            (top.is_enum() && enum_is_normal(top.as_enum().unwrap())) || top.is_model()
        }),
        TypeExprFilter::ActionInput => Arc::new(|top: &Node| {
            top.is_interface_declaration()
        }),
    }
}

fn struct_is_builtin(struct_declaration: &StructDeclaration) -> bool {
    let str_path = struct_declaration.str_path();
    if str_path.len() != 2 {
        return false;
    }
    if str_path.first().unwrap() != &"std" {
        return false;
    }
    let last = *str_path.last().unwrap();
    vec!["String", "Bool", "Null", "Int", "Int64", "Float", "Float32", "Decimal", "ObjectId", "Date", "DateTime", "Array", "Dictionary"].contains(&last)
}

fn enum_is_normal(enum_declaration: &Enum) -> bool {
    !enum_declaration.interface && !enum_declaration.option
}