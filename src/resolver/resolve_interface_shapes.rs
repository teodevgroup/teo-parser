use std::collections::BTreeMap;
use indexmap::indexmap;
use maplit::btreemap;
use crate::ast::generics::GenericsDeclaration;
use crate::ast::interface::InterfaceDeclaration;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::Type;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_shape_cache_for_interface_declaration<'a>(
    interface_declaration: &'a InterfaceDeclaration,
    generics: &Vec<Type>,
    context: &'a ResolverContext<'a>,
) -> Type {
    let mut map = indexmap! {};
    let generics_map = calculate_generics_map(interface_declaration.generics_declaration(), generics);
    for field in interface_declaration.fields() {
        let t = field.type_expr().resolved().replace_generics(&generics_map);
        map.insert(field.name().to_owned(), t.clone());
        if let Some((reference, gen)) = t.as_interface_object() {
            let declaration = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
            if declaration.shape(gen).is_none() {
                declaration.set_shape(gen.clone(), resolve_shape_cache_for_interface_declaration(declaration, gen, context));
            }
        }
    }
    for extend in interface_declaration.extends() {
        if let Some((reference, gen)) = extend.resolved().replace_generics(&generics_map).as_interface_object() {
            let declaration = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
            if declaration.shape(gen).is_none() {
                declaration.set_shape(gen.clone(), resolve_shape_cache_for_interface_declaration(declaration, gen, context));
            }
        }
    }
    Type::SynthesizedShape(SynthesizedShape::new(map))
}

pub(super) fn calculate_generics_map<'a>(
    generics_declaration: Option<&'a GenericsDeclaration>,
    types: &'a Vec<Type>,
) -> BTreeMap<String, Type> {
    if let Some(generics_declaration) = generics_declaration {
        if generics_declaration.identifiers.len() == types.len() {
            return generics_declaration.identifiers().enumerate().map(|(index, identifier)| (identifier.name().to_owned(), types.get(index).unwrap().clone())).collect();
        }
    }
    btreemap!{}
}

pub(super) fn collect_inputs_from_interface_declaration_shape_cache<'a>(interface: &'a InterfaceDeclaration, gens: &Vec<Type>, context: &'a ResolverContext<'a>) -> Vec<SynthesizedShape> {
    let mut input = vec![interface.shape(gens).unwrap().as_synthesized_shape().unwrap().clone()];
    let generics_map = calculate_generics_map(interface.generics_declaration(), gens);
    for extend in interface.extends() {
        if let Some((reference, gen)) = extend.resolved().replace_generics(&generics_map).as_interface_object() {
            let declaration = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
            input.extend(collect_inputs_from_interface_declaration_shape_cache(declaration, gen, context));
        }
    }
    input
}