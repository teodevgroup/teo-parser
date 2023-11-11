use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::pipeline_item_declaration::{PipelineItemDeclaration, PipelineItemDeclarationVariant};
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_generics::{resolve_generics_constraint, resolve_generics_declaration};
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_pipeline_item_declaration<'a>(pipeline_item_declaration: &'a PipelineItemDeclaration, context: &'a ResolverContext<'a>) {
    if let Some(generics_declaration) = &pipeline_item_declaration.generics_declaration {
        resolve_generics_declaration(generics_declaration, &vec![], context);
        if let Some(generics_constraint) = &pipeline_item_declaration.generics_constraint {
            resolve_generics_constraint(generics_constraint, context, generics_declaration, pipeline_item_declaration.define_availability);
        }
    }
    if let Some(argument_list_declaration) = &pipeline_item_declaration.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            &if let Some(generics_declaration) = pipeline_item_declaration.generics_declaration.as_ref() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = pipeline_item_declaration.generics_constraint.as_ref() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            context,
            pipeline_item_declaration.define_availability,
        );
    }
    if let Some(input_type) = &pipeline_item_declaration.input_type {
        resolve_type_expr(
            input_type,
            &if let Some(generics_declaration) = pipeline_item_declaration.generics_declaration.as_ref() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = pipeline_item_declaration.generics_constraint.as_ref() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            &btreemap!{},
            context,
            pipeline_item_declaration.define_availability,
        );
    }
    if let Some(output_type) = &pipeline_item_declaration.output_type {
        resolve_type_expr(
            output_type,
            &if let Some(generics_declaration) = pipeline_item_declaration.generics_declaration.as_ref() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = pipeline_item_declaration.generics_constraint.as_ref() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            &btreemap!{},
            context,
            pipeline_item_declaration.define_availability,
        );
    }
    for variant in &pipeline_item_declaration.variants {
        resolve_pipeline_item_declaration_variant(variant, context, pipeline_item_declaration.define_availability);
    }
}

fn resolve_pipeline_item_declaration_variant<'a>(
    pipeline_item_declaration_variant: &'a PipelineItemDeclarationVariant,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) {
    if let Some(generics_declaration) = &pipeline_item_declaration_variant.generics_declaration {
        resolve_generics_declaration(generics_declaration, &vec![], context);
        if let Some(generics_constraint) = &pipeline_item_declaration_variant.generics_constraint {
            resolve_generics_constraint(generics_constraint, context, generics_declaration, availability);
        }
    }
    if let Some(argument_list_declaration) = &pipeline_item_declaration_variant.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            &if let Some(generics_declaration) = pipeline_item_declaration_variant.generics_declaration.as_ref() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = pipeline_item_declaration_variant.generics_constraint.as_ref() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            context,
            availability,
        );
    }
    resolve_type_expr(
        &pipeline_item_declaration_variant.input_type,
        &if let Some(generics_declaration) = pipeline_item_declaration_variant.generics_declaration.as_ref() {
            vec![generics_declaration]
        } else {
            vec![]
        },
        &if let Some(generics_constraint) = pipeline_item_declaration_variant.generics_constraint.as_ref() {
            vec![generics_constraint]
        } else {
            vec![]
        },
        &btreemap! {},
        context,
        availability
    );
    resolve_type_expr(
        &pipeline_item_declaration_variant.output_type,
        &if let Some(generics_declaration) = pipeline_item_declaration_variant.generics_declaration.as_ref() {
            vec![generics_declaration]
        } else {
            vec![]
        },
        &if let Some(generics_constraint) = pipeline_item_declaration_variant.generics_constraint.as_ref() {
            vec![generics_constraint]
        } else {
            vec![]
        },
        &btreemap! {},
        context,
        availability
    );
}