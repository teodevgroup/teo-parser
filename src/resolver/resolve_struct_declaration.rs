use maplit::btreemap;
use crate::ast::struct_declaration::StructDeclaration;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_function_declaration::resolve_function_declaration;
use crate::resolver::resolve_generics::{resolve_generics_constraint, resolve_generics_declaration};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_struct_declaration<'a>(struct_declaration: &'a StructDeclaration, context: &'a ResolverContext<'a>) {
    if context.has_examined_default_path(&struct_declaration.string_path, struct_declaration.define_availability) {
        context.insert_duplicated_identifier(struct_declaration.identifier().span);
    }
    if let Some(generics_declaration) = &struct_declaration.generics_declaration {
        resolve_generics_declaration(generics_declaration, &vec![], context);
        if let Some(generics_constraint) = &struct_declaration.generics_constraint {
            resolve_generics_constraint(generics_constraint, context, generics_declaration, struct_declaration.define_availability);
        }
    }
    let r#type = Type::StructObject(Reference::new(struct_declaration.path.clone(), struct_declaration.string_path.clone()), if let Some(generics_declaration) = struct_declaration.generics_declaration.as_ref() {
        generics_declaration.identifiers.iter().map(|i| Type::GenericItem(i.name().to_owned())).collect()
    } else {
        vec![]
    });
    for function_declaration in &struct_declaration.function_declarations {
        resolve_function_declaration(
            function_declaration,
            struct_declaration.generics_declaration.as_ref(),
            struct_declaration.generics_constraint.as_ref(),
            &btreemap! {
                Keyword::SelfIdentifier => r#type.clone(),
            },
            context,
        )
    }
    context.add_examined_default_path(struct_declaration.string_path.clone(), struct_declaration.define_availability);
}
