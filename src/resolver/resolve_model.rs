use crate::ast::field::FieldHint;
use crate::ast::model::Model;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_model<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    if context.has_examined_model_path(&model.string_path) {
        context.insert_duplicated_model_error(model);
    }
    context.clear_examined_model_fields();
    // decorators
    for decorator in &model.decorators {
        //resolve_decorator(decorator, context, DecoratorClass::ModelDecorator);
    }
    // fields
    for field in &model.fields {
        //resolve_field(field, context, FieldHint::ModelField)
    }
    context.add_examined_model_path(model.string_path.clone());
}