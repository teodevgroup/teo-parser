use crate::ast::decorator_declaration::DecoratorDeclaration;
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
        Top::ActionGroup(_) => unreachable!(),
        Top::Interface(_) => unreachable!(),
        Top::Namespace(namespace) => completion_item_from_namespace(namespace),
        Top::DecoratorDeclaration(decorator_declaration) => completion_item_from_decorator_declaration(decorator_declaration),
        Top::PipelineItemDeclaration(_) => unreachable!(),
    }
}

pub(super) fn completion_item_from_namespace(namespace: &Namespace) -> CompletionItem {
    CompletionItem {
        label: namespace.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&namespace.string_path)),
        documentation: Some("namespace doc".to_owned()),
        detail: Some("detail".to_owned()),
    }
}

pub(super) fn completion_item_from_decorator_declaration(decorator_declaration: &DecoratorDeclaration) -> CompletionItem {
    CompletionItem {
        label: decorator_declaration.identifier.name.clone(),
        namespace_path: Some(readable_namespace_path(&decorator_declaration.string_path)),
        documentation: decorator_declaration.comment.as_ref().map(|c| {
            format!("{}{}", c.name.as_ref().map_or("".to_owned(), |n| format!("**{}**\n", n)), c.desc.as_ref().map_or("", |s| s.as_str()))
        }),
        detail: None,
    }
}