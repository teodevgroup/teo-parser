use crate::ast::comment::Comment;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::field::Field;
use crate::ast::namespace::Namespace;
use crate::ast::top::Top;
use crate::completion::completion_item::CompletionItem;
use crate::utils::output::readable_namespace_path;

pub(super) fn completion_item_from_top(top: &Top) -> CompletionItem {
    match top {
        Top::Import(_) => unreachable!(),
        Top::Config(_) => unreachable!(),
        Top::ConfigDeclaration(_) => unreachable!(),
        Top::Constant(_) => unreachable!(),
        Top::Enum(_) => unreachable!(),
        Top::Model(_) => unreachable!(),
        Top::DataSet(_) => unreachable!(),
        Top::Middleware(_) => unreachable!(),
        Top::HandlerGroup(_) => unreachable!(),
        Top::Interface(_) => unreachable!(),
        Top::Namespace(namespace) => completion_item_from_namespace(namespace),
        Top::DecoratorDeclaration(decorator_declaration) => completion_item_from_decorator_declaration(decorator_declaration),
        Top::PipelineItemDeclaration(_) => unreachable!(),
        Top::StructDeclaration(_) => unreachable!(),
        Top::UseMiddlewareBlock(_) => unreachable!(),
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