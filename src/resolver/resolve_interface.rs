use std::collections::{BTreeMap, BTreeSet};
use indexmap::{indexmap, IndexMap};
use maplit::{btreemap, btreeset};
use crate::ast::interface::{InterfaceDeclaration, InterfaceDeclarationResolved};
use crate::ast::span::Span;
use crate::ast::type_expr::TypeExpr;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::Type;
use crate::resolver::resolve_field::{FieldParentType, resolve_field_class, resolve_field_types};
use crate::resolver::resolve_generics::{resolve_generics_constraint, resolve_generics_declaration};
use crate::resolver::resolve_interface_shapes::calculate_generics_map;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_interface_declaration_types<'a>(interface_declaration: &'a InterfaceDeclaration, context: &'a ResolverContext<'a>) {
    if context.has_examined_default_path(&interface_declaration.string_path, interface_declaration.define_availability) {
        context.insert_duplicated_identifier(interface_declaration.identifier().span);
    }
    *interface_declaration.actual_availability.borrow_mut() = context.current_availability();
    if let Some(generics_declaration) = interface_declaration.generics_declaration() {
        resolve_generics_declaration(generics_declaration, &vec![], context);
        if let Some(generics_constraint) = interface_declaration.generics_constraint() {
            resolve_generics_constraint(generics_constraint, context, generics_declaration, interface_declaration.define_availability);
        }
    }
    for extend in interface_declaration.extends() {
        resolve_type_expr(
            extend,
            &if let Some(generics_declaration) = interface_declaration.generics_declaration() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = interface_declaration.generics_constraint() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            &btreemap! {},
            context,
            interface_declaration.define_availability,
        );
        if !extend.resolved().is_interface_object() && !extend.resolved().is_synthesized_shape() && !extend.resolved().is_synthesized_shape_reference() {
            context.insert_diagnostics_error(extend.span(), "type is invalid for extending");
        }
    }
    for partial_field in interface_declaration.partial_fields() {
        context.insert_diagnostics_error(partial_field.span, "partial field");
    }
    for field in interface_declaration.fields() {
        resolve_field_class(
            field,
            FieldParentType::Interface,
            context,
        );
        resolve_field_types(
            field,
            interface_declaration.generics_declaration(),
            interface_declaration.generics_constraint(),
            context
        );
    }
    context.add_examined_default_path(interface_declaration.string_path.clone(), interface_declaration.define_availability);
    let mut map = indexmap! {};
    let mut existing_keys = vec![];
    for field in interface_declaration.fields() {
        if !existing_keys.contains(&field.identifier().name()) {
            map.insert(field.identifier().name().to_owned(), field.type_expr().resolved().clone());
            existing_keys.push(field.identifier().name());
        }
    }
    interface_declaration.resolve(InterfaceDeclarationResolved::new(SynthesizedShape::new(map)));
}

pub(super) fn resolve_interface_declaration_shapes<'a>(interface_declaration: &'a InterfaceDeclaration, context: &'a ResolverContext<'a>) {
    let mut map = indexmap! {};
    let mut existing_keys = vec![];
    let mut extending_dependencies = btreeset![interface_declaration.str_path()];
    for extend in interface_declaration.extends() {
        insert_extend_into_interface_map(extend.span(), extend, context, &mut map, &mut existing_keys, &mut extending_dependencies, vec![]);
    }
    for field in interface_declaration.fields() {
        if existing_keys.contains(&field.identifier().name) {
            context.insert_diagnostics_error(field.identifier().span, format!("key '{}' is duplicated", field.identifier().name()));
        } else {
            map.insert(field.identifier().name().to_owned(), field.type_expr().resolved().clone());
            existing_keys.push(field.identifier().name.clone());
        }
    }
    let shape = SynthesizedShape::new(map);
    interface_declaration.resolved_mut().shape = Some(shape);
}

fn insert_extend_into_interface_map<'a>(error_span: Span, extend: &'a TypeExpr, context: &'a ResolverContext<'a>, map: &mut IndexMap<String, Type>, existing_keys: &mut Vec<String>, extending_dependencies: &mut BTreeSet<Vec<&'a str>>, mut generics_maps: Vec<BTreeMap<String, Type>>) {
    if let Some((reference, types)) = extend.resolved().as_interface_object() {
        if extending_dependencies.contains(&reference.str_path()) {
            context.insert_diagnostics_error(error_span, "circular extending found");
        } else {
            extending_dependencies.insert(reference.str_path());
            let interface_for_extending = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
            let generics_map = calculate_generics_map(interface_for_extending.generics_declaration(), types);
            generics_maps.push(generics_map);
            for extend_extend in interface_for_extending.extends() {
                insert_extend_into_interface_map(error_span, extend_extend, context, map, existing_keys, extending_dependencies, generics_maps.clone());
            }
            let mut shape_for_this_interface = interface_for_extending.resolved().base_shape().clone();
            for alter in generics_maps.iter().rev() {
                shape_for_this_interface = shape_for_this_interface.replace_generics(alter);
            }
            insert_synthesized_shape_into_interface_map(error_span, &shape_for_this_interface, context, map, existing_keys);
        }
    } else if let Some(synthesized_shape) = extend.resolved().as_synthesized_shape() {
        insert_synthesized_shape_into_interface_map(error_span, synthesized_shape, context, map, existing_keys);
    } else if let Some(synthesized_shape_reference) = extend.resolved().as_synthesized_shape_reference() {
        if let Some(t) = synthesized_shape_reference.fetch_synthesized_definition(context.schema) {
            if let Some(synthesized_shape) = t.as_synthesized_shape() {
                insert_synthesized_shape_into_interface_map(error_span, synthesized_shape, context, map, existing_keys);
            } else {
                context.insert_diagnostics_error(error_span, format!("{} is invalid for extending", t));
            }
        }
    }
}

fn insert_synthesized_shape_into_interface_map<'a>(error_span: Span, synthesized_shape: &SynthesizedShape, context: &'a ResolverContext<'a>, map: &mut IndexMap<String, Type>, existing_keys: &mut Vec<String>) {
    for (k, v) in synthesized_shape.iter() {
        if existing_keys.contains(k) {
            context.insert_diagnostics_error(error_span, format!("key '{}' is duplicated", k));
        } else {
            map.insert(k.to_owned(), v.clone());
            existing_keys.push(k.clone());
        }
    }
}
