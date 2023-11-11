use crate::availability::Availability;
use crate::ast::generics::GenericsDeclaration;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::type_expr::{TypeExprKind, TypeItem};
use crate::definition::definition::Definition;
use crate::search::search_identifier_path::{search_identifier_path_names_with_filter_to_path, search_identifier_path_names_with_filter_to_type_and_value};
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn jump_to_definition_in_type_expr_kind(
    schema: &Schema,
    source: &Source,
    type_expr: &TypeExprKind,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    generics_declarations: &Vec<&GenericsDeclaration>,
    availability: Availability,
) -> Vec<Definition> {
    match type_expr {
        TypeExprKind::Expr(type_expr) => jump_to_definition_in_type_expr_kind(
            schema,
            source,
            type_expr.as_ref(),
            namespace_path,
            line_col,
            generics_declarations,
            availability
        ),
        TypeExprKind::BinaryOp(b) => if b.lhs.span().contains_line_col(line_col) {
            jump_to_definition_in_type_expr_kind(
                schema,
                source,
                b.lhs.as_ref(),
                namespace_path,
                line_col,
                generics_declarations,
                availability
            )
        } else if b.rhs.span().contains_line_col(line_col) {
            jump_to_definition_in_type_expr_kind(
                schema,
                source,
                b.rhs.as_ref(),
                namespace_path,
                line_col,
                generics_declarations,
                availability
            )
        } else {
            vec![]
        }
        TypeExprKind::TypeGroup(g) => if g.kind.span().contains_line_col(line_col) {
            jump_to_definition_in_type_expr_kind(
                schema,
                source,
                g.kind.as_ref(),
                namespace_path,
                line_col,
                generics_declarations,
                availability
            )
        } else {
            vec![]
        }
        TypeExprKind::TypeTuple(type_tuple) => {
            for t in &type_tuple.kinds {
                if t.span().contains_line_col(line_col) {
                    return jump_to_definition_in_type_expr_kind(
                        schema,
                        source,
                        t,
                        namespace_path,
                        line_col,
                        generics_declarations,
                        availability
                    );
                }
            }
            vec![]
        }
        TypeExprKind::TypeSubscript(type_subscript) => if type_subscript.type_expr.span().contains_line_col(line_col) {
            return jump_to_definition_in_type_expr_kind(
                schema,
                source,
                type_subscript.type_expr.as_ref(),
                namespace_path,
                line_col,
                generics_declarations,
                availability
            );
        } else if type_subscript.type_item.span.contains_line_col(line_col) {
            jump_to_definition_in_type_item(
                schema,
                source,
                &type_subscript.type_item,
                namespace_path,
                line_col,
                generics_declarations,
                availability
            )
        } else {
            vec![]
        }
        TypeExprKind::FieldReference(_) => vec![],
        TypeExprKind::TypeItem(type_item) => jump_to_definition_in_type_item(
            schema,
            source,
            type_item,
            namespace_path,
            line_col,
            generics_declarations,
            availability
        )
    }
}

fn jump_to_definition_in_type_item(
    schema: &Schema,
    source: &Source,
    type_item: &TypeItem,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    generics_declarations: &Vec<&GenericsDeclaration>,
    availability: Availability,
) -> Vec<Definition> {
    for gen in &type_item.generics {
        if gen.span().contains_line_col(line_col) {
            return jump_to_definition_in_type_expr_kind(
                schema, 
                source,
                gen,
                namespace_path,
                line_col,
                generics_declarations,
                availability
            );
        }
    }
    if type_item.identifier_path.span.contains_line_col(line_col) {
        if type_item.identifier_path.identifiers.len() == 1 {
            let identifier = type_item.identifier_path.identifiers.get(0).unwrap();
            for generics_declaration in generics_declarations {
                if let Some(i) = generics_declaration.identifiers.iter().find(|i| i.name() == identifier.name()) {
                    return vec![Definition {
                        path: schema.source(generics_declaration.source_id()).unwrap().file_path.clone(),
                        selection_span: identifier.span,
                        target_span: generics_declaration.span,
                        identifier_span: i.span,
                    }]
                }
            }
        }
        let mut user_typed_spaces = vec![];
        let mut selector_span = None;
        for identifier in type_item.identifier_path.identifiers.iter() {
            if identifier.span.contains_line_col(line_col) {
                user_typed_spaces.push(identifier.name());
                selector_span = Some(identifier.span);
                break
            } else {
                user_typed_spaces.push(identifier.name());
            }
        }
        let reference = search_identifier_path_names_with_filter_to_path(&user_typed_spaces, schema, source, namespace_path, &top_filter_for_reference_type(ReferenceSpace::Default), availability);
        if let Some(reference) = reference {
            let top = schema.find_top_by_path(&reference).unwrap();
            return vec![Definition {
                path: schema.source(top.source_id()).unwrap().file_path.clone(),
                selection_span: selector_span.unwrap(),
                target_span: top.span(),
                identifier_span: top.identifier_span().unwrap(),
            }]
        }
    }
    vec![]
}