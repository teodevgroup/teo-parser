use crate::ast::action::{ActionDeclaration, ActionGroupDeclaration};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_action_group<'a>(
    action_group: &'a ActionGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    for action_declaration in &action_group.action_declarations {
        resolve_action_declaration(action_declaration, context)
    }
}

pub(super) fn resolve_action_declaration<'a>(
    action_declaration: &'a ActionDeclaration,
    context: &'a ResolverContext<'a>,
) {
    if context.has_examined_default_path(&action_declaration.string_path) {

    }

}