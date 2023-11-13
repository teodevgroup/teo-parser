use crate::ast::comment::Comment;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::constant::Constant;
use crate::ast::data_set::DataSet;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::field::Field;
use crate::ast::handler::HandlerGroupDeclaration;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::model::Model;
use crate::ast::namespace::Namespace;
use crate::ast::node::Node;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::r#enum::Enum;
use crate::ast::struct_declaration::StructDeclaration;
use crate::completion::completion_item::CompletionItem;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::utils::output::readable_namespace_path;

pub(super) fn completion_item_from_top(top: &Node) -> CompletionItem {
    match top {
        Node::Import(_) => unreachable!(),
        Node::Config(c) => completion_item_from_config(c),
        Node::ConfigDeclaration(c) => completion_item_from_config_declaration(c),
        Node::Constant(c) => completion_item_from_constant(c),
        Node::Enum(e) => completion_item_from_enum(e),
        Node::Model(m) => completion_item_from_model(m),
        Node::DataSet(d) => completion_item_from_data_set(d),
        Node::MiddlewareDeclaration(m) => completion_item_from_middleware(m),
        Node::HandlerGroupDeclaration(h) => completion_item_from_handler_group(h),
        Node::InterfaceDeclaration(i) => completion_item_from_interface(i),
        Node::Namespace(namespace) => completion_item_from_namespace(namespace),
        Node::DecoratorDeclaration(decorator_declaration) => completion_item_from_decorator_declaration(decorator_declaration),
        Node::PipelineItemDeclaration(p) => completion_item_from_pipeline_item_declaration(p),
        Node::StructDeclaration(s) => completion_item_from_struct_declaration(s),
        Node::UseMiddlewareBlock(_) => unreachable!(),
    }
}

fn documentation_from_comment(comment: Option<&Comment>) -> Option<String> {
    comment.map(|c| {
        format!("{}{}", c.name.as_ref().map_or("".to_owned(), |n| format!("**{}**\n", n)), c.desc.as_ref().map_or("", |s| s.as_str()))
    })
}

pub(super) fn completion_item_from_namespace(namespace: &Namespace) -> CompletionItem {
    CompletionItem {
        label: namespace.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&namespace.string_path)),
        documentation: documentation_from_comment(namespace.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_decorator_declaration(decorator_declaration: &DecoratorDeclaration) -> CompletionItem {
    CompletionItem {
        label: decorator_declaration.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&decorator_declaration.string_path)),
        documentation: documentation_from_comment(decorator_declaration.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_field(field: &Field) -> CompletionItem {
    CompletionItem {
        label: field.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&field.string_path)),
        documentation: documentation_from_comment(field.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_config(config: &Config) -> CompletionItem {
    CompletionItem {
        label: config.name().to_owned(),
        namespace_path: Some(readable_namespace_path(&config.string_path)),
        documentation: None,
        detail: None,
    }
}

pub(super) fn completion_item_from_config_declaration(config_declaration: &ConfigDeclaration) -> CompletionItem {
    CompletionItem {
        label: config_declaration.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&config_declaration.string_path)),
        documentation: documentation_from_comment(config_declaration.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_constant(constant: &Constant) -> CompletionItem {
    CompletionItem {
        label: constant.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&constant.string_path)),
        documentation: None,
        detail: None,
    }
}

pub(super) fn completion_item_from_enum(e: &Enum) -> CompletionItem {
    CompletionItem {
        label: e.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&e.string_path)),
        documentation: documentation_from_comment(e.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_model(model: &Model) -> CompletionItem {
    CompletionItem {
        label: model.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&model.string_path)),
        documentation: documentation_from_comment(model.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_data_set(data_set: &DataSet) -> CompletionItem {
    CompletionItem {
        label: data_set.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&data_set.string_path)),
        documentation: None,
        detail: None,
    }
}

pub(super) fn completion_item_from_middleware(middleware: &MiddlewareDeclaration) -> CompletionItem {
    CompletionItem {
        label: middleware.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&middleware.string_path)),
        documentation: None,
        detail: None,
    }
}

pub(super) fn completion_item_from_handler_group(handler_group: &HandlerGroupDeclaration) -> CompletionItem {
    CompletionItem {
        label: handler_group.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&handler_group.string_path)),
        documentation: documentation_from_comment(handler_group.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_interface(interface_declaration: &InterfaceDeclaration) -> CompletionItem {
    CompletionItem {
        label: interface_declaration.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&interface_declaration.string_path)),
        documentation: documentation_from_comment(interface_declaration.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_pipeline_item_declaration(pipeline_item_declaration: &PipelineItemDeclaration) -> CompletionItem {
    CompletionItem {
        label: pipeline_item_declaration.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&pipeline_item_declaration.string_path)),
        documentation: documentation_from_comment(pipeline_item_declaration.comment.as_ref()),
        detail: None,
    }
}

pub(super) fn completion_item_from_struct_declaration(struct_declaration: &StructDeclaration) -> CompletionItem {
    CompletionItem {
        label: struct_declaration.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&struct_declaration.string_path)),
        documentation: documentation_from_comment(struct_declaration.comment.as_ref()),
        detail: None,
    }
}