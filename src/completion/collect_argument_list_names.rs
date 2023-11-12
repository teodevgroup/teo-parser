use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;

pub(super) fn collect_argument_list_names_from_pipeline_item_declaration(pipeline_item_declaration: &PipelineItemDeclaration) -> Vec<Vec<&str>> {
    let mut result = vec![];
    if let Some(argument_list_declaration) = &pipeline_item_declaration.argument_list_declaration {
        result.push(collect_argument_list_names_from_argument_list_declaration(argument_list_declaration));
    }
    for variant in &pipeline_item_declaration.variants {
        if let Some(argument_list_declaration) = &variant.argument_list_declaration {
            result.push(collect_argument_list_names_from_argument_list_declaration(argument_list_declaration));
        }
    }
    result
}

pub(super) fn collect_argument_list_names_from_decorator_declaration(decorator_declaration: &DecoratorDeclaration) -> Vec<Vec<&str>> {
    let mut result = vec![];
    if let Some(argument_list_declaration) = &decorator_declaration.argument_list_declaration {
        result.push(collect_argument_list_names_from_argument_list_declaration(argument_list_declaration));
    }
    for variant in &decorator_declaration.variants {
        if let Some(argument_list_declaration) = &variant.argument_list_declaration {
            result.push(collect_argument_list_names_from_argument_list_declaration(argument_list_declaration));
        }
    }
    result
}

pub(super) fn collect_argument_list_names_from_argument_list_declaration(argument_list_declaration: &ArgumentListDeclaration) -> Vec<&str> {
    argument_list_declaration.argument_declarations.iter().map(|a| a.name.name()).collect()
}