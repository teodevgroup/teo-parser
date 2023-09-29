use crate::ast::model::Model;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_model(model: &Model, context: &mut ResolverContext) {
    if context.has_examined_model_path(&model.string_path) {
        context.insert_duplicated_model_error(model);
    }
}