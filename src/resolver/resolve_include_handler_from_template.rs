use maplit::btreemap;
use crate::ast::include_handler_from_template::{IncludeHandlerFromTemplate, IncludeHandlerFromTemplateResolved};
use crate::ast::model::Model;
use crate::ast::reference_space::ReferenceSpace;
use crate::availability::Availability;
use crate::r#type::keyword::Keyword;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_identifier::{resolve_identifier_path_names_with_filter_to_top};
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::{top_filter_for_handler_template};

pub(super) fn resolve_include_handler_from_template_decorators<'a>(
    include_handler_from_template: &'a IncludeHandlerFromTemplate,
    context: &'a ResolverContext<'a>,
    model: &'a Model,
) {
    if context.has_examined_default_path(&include_handler_from_template.string_path, Availability::default()) {
        context.insert_duplicated_identifier(include_handler_from_template.identifier_path().span);
    }
    context.add_examined_default_path(include_handler_from_template.string_path.clone(), Availability::default());
    let template_path = include_handler_from_template.identifier_path();
    if let Some(template_node) = resolve_identifier_path_names_with_filter_to_top(
        &template_path.names(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_handler_template(),
        context.current_availability()
    ) {
        let template = template_node.as_handler_template_declaration().unwrap();
        let mut resolved = IncludeHandlerFromTemplateResolved {
            input_type: None,
            output_type: Type::Any,
            template_path: template.string_path.clone(),
        };
        if let Some(template_input_type_expr) = template.input_type() {
            let input_type = template_input_type_expr.resolved();
            resolved.input_type = Some(type_replace_generics_for_handler_template_type(input_type, model));
        }
        let output_type = template.output_type().resolved();
        resolved.output_type = type_replace_generics_for_handler_template_type(output_type, model);
        include_handler_from_template.resolve(resolved);
        let mut keywords_map = btreemap!{};
        keywords_map.insert(Keyword::SelfIdentifier, Type::ModelObject(Reference::new(model.path.clone(), model.string_path.clone())));
        for decorator in include_handler_from_template.decorators() {
            resolve_decorator(decorator, context, &keywords_map, ReferenceSpace::HandlerDecorator);
        }
    } else {
        context.insert_diagnostics_error(include_handler_from_template.identifier_path().span(), "handler template definition is not found");
    }
}

fn type_replace_generics_for_handler_template_type(original: &Type, model: &Model) -> Type {
    original.replace_keywords(&btreemap! {
        Keyword::SelfIdentifier => Type::ModelObject(Reference::new(model.path.clone(), model.string_path.clone())),
    })
}