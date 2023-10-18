use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::generics::GenericsDeclaration;
use crate::r#type::r#type::Type;
use crate::resolver::resolver_context::ResolverContext;

pub(crate) fn resolve_type_contains_type<'a, F>(r#type: &Type, f: F, context: &'a ResolverContext<'a>) -> bool where F: Fn(&Type) -> bool {
    let matcher = |t: &Type, f: &dyn Fn(&Type) -> bool| { resolve_type_contains_type(t, f, context) };
    if matcher(r#type, &f) { return true; }
    match r#type {
        Type::Array(t) => matcher(t.as_ref(), &f),
        Type::Dictionary(t) => matcher(t.as_ref(), &f) || matcher(&Type::String, &f),
        Type::Tuple(t) => t.iter().find(|t| matcher(*t, &f)).is_some(),
        Type::Range(t) => matcher(t.as_ref(), &f),
        Type::Union(u) => u.iter().find(|t| matcher(*t, &f)).is_some(),
        Type::InterfaceObject(path, types, _) => {
            let interface = context.schema.find_top_by_path(path).unwrap().as_interface_declaration().unwrap();
            let generics_map = calculate_generics_map(interface.generics_declaration.as_ref(), types);
            for field in &interface.fields {
                if matcher(&field.type_expr.resolved().replace_generics(&generics_map), &f) {
                    return true;
                }
            }
            for extend in &interface.extends {
                if matcher(extend.resolved(), &f) {
                    return true;
                }
            }
            return false;
        },
        Type::Optional(t) => matcher(t.as_ref(), &f),
        _ => false,
    }
}

pub(super) fn calculate_generics_map<'a>(
    generics_declaration: Option<&'a GenericsDeclaration>,
    types: &'a Vec<Type>,
) -> BTreeMap<String, Type> {
    if let Some(generics_declaration) = generics_declaration {
        if generics_declaration.identifiers.len() == types.len() {
            return generics_declaration.identifiers.iter().enumerate().map(|(index, identifier)| (identifier.name().to_owned(), types.get(index).unwrap().clone())).collect();
        }
    }
    btreemap!{}
}