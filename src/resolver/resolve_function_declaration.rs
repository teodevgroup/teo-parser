use std::collections::BTreeMap;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_generics::{resolve_generics_constraint, resolve_generics_declaration};
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_function_declaration<'a>(
    function_declaration: &'a FunctionDeclaration,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    keywords_map: &BTreeMap<Keyword, &Type>,
    context: &'a ResolverContext<'a>,
) {
    if let Some(generics_declaration) = &function_declaration.generics_declaration {
        resolve_generics_declaration(generics_declaration, context);
        if let Some(generics_constraint) = &function_declaration.generics_constraint {
            resolve_generics_constraint(generics_constraint, context, generics_declaration);
        }
    }
    let mut generics_declarations = vec![];
    let mut generics_constraints = vec![];
    if let Some(generics_declaration) = generics_declaration {
        generics_declarations.push(generics_declaration);
    }
    if let Some(generics_constraint) = generics_constraint {
        generics_constraints.push(generics_constraint);
    }
    if let Some(generics_declaration) = &function_declaration.generics_declaration {
        generics_declarations.push(generics_declaration);
    }
    if let Some(generics_constraint) = &function_declaration.generics_constraint {
        generics_constraints.push(generics_constraint);
    }
    if let Some(argument_list_declaration) = &function_declaration.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            &generics_declarations,
            &generics_constraints,
            context
        );
    }
    resolve_type_expr(
        &function_declaration.return_type,
        &generics_declarations,
        &generics_constraints,
        keywords_map,
        context
    );
}