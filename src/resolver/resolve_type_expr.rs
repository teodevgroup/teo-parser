use std::collections::BTreeMap;
use crate::ast::arity::Arity;
use crate::availability::Availability;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::type_expr::{TypeExpr, TypeExprKind, TypeItem, TypeOperator};
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_identifier::resolve_identifier_path;
use crate::resolver::resolve_interface_shapes::calculate_generics_map;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_type_expr<'a>(
    type_expr: &'a TypeExpr,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    keywords_map: &BTreeMap<Keyword, Type>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) {
    type_expr.resolve(
        resolve_type_expr_kind(
            &type_expr.kind,
            generics_declaration,
            generics_constraint,
            context,
            availability,
        ).replace_keywords(&keywords_map)
    )
}

fn resolve_type_expr_kind<'a>(
    type_expr_kind: &'a TypeExprKind,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) -> Type {
    match type_expr_kind {
        TypeExprKind::Expr(expr) => {
            resolve_type_expr_kind(
                expr,
                generics_declaration,
                generics_constraint,
                context,
                availability
            )
        }
        TypeExprKind::BinaryOp(binary_op) => {
            match binary_op.op {
                TypeOperator::BitOr => {
                    let lhs = resolve_type_expr_kind(
                        binary_op.lhs.as_ref(),
                        generics_declaration,
                        generics_constraint,
                        context,
                        availability,
                    );
                    let rhs = resolve_type_expr_kind(
                        binary_op.rhs.as_ref(),
                        generics_declaration,
                        generics_constraint,
                        context,
                        availability,
                    );
                    let retval = Type::Union(vec![lhs, rhs]);
                    retval
                }
            }
        }
        TypeExprKind::TypeItem(type_item) => {
            resolve_type_item(
                type_item,
                generics_declaration,
                generics_constraint,
                context,
                availability,
            )
        }
        TypeExprKind::TypeGroup(g) => {
            let mut resolved = resolve_type_expr_kind(
                g.kind.as_ref(),
                generics_declaration,
                generics_constraint,
                context,
                availability,
            );
            if !resolved.is_optional() && g.item_optional {
                resolved = Type::Optional(Box::new(resolved));
            }
            if !g.arity.is_scalar() {
                match g.arity {
                    Arity::Array => resolved = Type::Array(Box::new(resolved)),
                    Arity::Dictionary => resolved = Type::Dictionary(Box::new(resolved)),
                    _ => ()
                };
                if g.collection_optional {
                    resolved = Type::Optional(Box::new(resolved));
                }
            }
            resolved
        }
        TypeExprKind::TypeTuple(t) => {
            let mut resolved = Type::Tuple(t.kinds.iter().map(|k| resolve_type_expr_kind(
                k,
                generics_declaration,
                generics_constraint,
                context,
                availability,
            )).collect());
            if !resolved.is_optional() && t.item_optional {
                resolved = Type::Optional(Box::new(resolved));
            }
            if !t.arity.is_scalar() {
                match t.arity {
                    Arity::Array => resolved = Type::Array(Box::new(resolved)),
                    Arity::Dictionary => resolved = Type::Dictionary(Box::new(resolved)),
                    _ => ()
                };
                if t.collection_optional {
                    resolved = Type::Optional(Box::new(resolved));
                }
            }
            resolved
        }
        TypeExprKind::TypeSubscript(subscript) => {
            let mut resolved = Type::FieldType(
                Box::new(resolve_type_item(&subscript.type_item, generics_declaration, generics_constraint, context, availability)),
                Box::new(resolve_type_expr_kind(&subscript.type_expr, generics_declaration, generics_constraint, context, availability)),
            );
            if !resolved.is_optional() && subscript.item_optional {
                resolved = Type::Optional(Box::new(resolved));
            }
            if !subscript.arity.is_scalar() {
                match subscript.arity {
                    Arity::Array => resolved = Type::Array(Box::new(resolved)),
                    Arity::Dictionary => resolved = Type::Dictionary(Box::new(resolved)),
                    _ => ()
                };
                if subscript.collection_optional {
                    resolved = Type::Optional(Box::new(resolved));
                }
            }
            resolved
        }
        TypeExprKind::FieldName(r) => {
            Type::FieldName(r.identifier.name().to_string())
        }
    }
}

fn resolve_type_item<'a>(
    type_item: &'a TypeItem,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) -> Type {
    let names = type_item.identifier_path.names();
    let mut base = if names.len() == 1 {
        let name = *names.get(0).unwrap();
        type_item_builtin_match(name, type_item, generics_declaration, generics_constraint, context, availability)
    } else {
        None
    };
    if base.is_none() {
        if let Some(resolved) = resolve_identifier_path(&type_item.identifier_path, context, ReferenceSpace::Default, availability) {
            base = match resolved.r#type() {
                Type::ModelReference(r) => Some(Type::ModelObject(r.clone())),
                Type::EnumReference(r) => Some(Type::EnumVariant(r.clone())),
                Type::InterfaceReference(r, _) => Some(Type::InterfaceObject(r.clone(), type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect())),
                Type::StructReference(r, _) => Some(Type::StructReference(r.clone(), type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect())),
                _ => None,
            };
        }
        if base.is_none() {
            context.insert_diagnostics_error(type_item.identifier_path.span, "unknown type");
            base = Some(Type::Undetermined);
        }
    }
    if type_item.item_optional {
        base = Some(Type::Optional(Box::new(base.unwrap())));
    }
    if !type_item.arity.is_scalar() {
        match type_item.arity {
            Arity::Array => base = Some(Type::Array(Box::new(base.unwrap()))),
            Arity::Dictionary => base = Some(Type::Dictionary(Box::new(base.unwrap()))),
            _ => (),
        }
        if type_item.collection_optional {
            base = Some(Type::Optional(Box::new(base.unwrap())))
        }
    }
    base.unwrap()
}

fn type_item_builtin_match<'a>(
    name: &str,
    type_item: &'a TypeItem,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) -> Option<Type> {
    match name {
        "Ignored" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Ignored)
        },
        "Any" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Any)
        },
        "Union" => {
            check_generics_amount_multiple(type_item, context);
            Some(Type::Union(type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect()))
        },
        "Enumerable" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Enumerable(Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
            }))))
        },
        "Optional" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Optional(Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
            }))))
        },
        "FieldType" => {
            check_generics_amount(2, type_item, context);
            if type_item.generics.len() != 2 {
                return Some(Type::Undetermined);
            }
            let t = type_item.generics.get(0).unwrap();
            let f = type_item.generics.get(1).unwrap();
            let Some(field_ref) = f.as_field_reference() else {
                context.insert_diagnostics_error(f.span(), "type is not field reference");
                return Some(Type::Undetermined);
            };
            let inner_type = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
            if let Some(reference) = inner_type.as_model_object() {
                let model = context.schema.find_top_by_path(reference.path()).unwrap().as_model().unwrap();
                if let Some(field) = model.fields.iter().find(|f| f.identifier.name() == field_ref.identifier.name()) {
                    Some(field.type_expr.resolved().clone())
                } else {
                    context.insert_diagnostics_error(f.span(), "field not found");
                    Some(Type::Undetermined)
                }
            } else if let Some((reference, interface_generics)) = inner_type.as_interface_object() {
                let interface = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
                let map = calculate_generics_map(interface.generics_declaration.as_ref(), interface_generics);
                if let Some(field) = interface.fields.iter().find(|f| f.identifier.name() == field_ref.identifier.name()) {
                    Some(field.type_expr.resolved().replace_generics(&map))
                } else {
                    context.insert_diagnostics_error(f.span(), "field not found");
                    Some(Type::Undetermined)
                }
            } else {
                context.insert_diagnostics_error(t.span(), "model or interface not found");
                Some(Type::Undetermined)
            }
        },
        "Self" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Keyword(Keyword::SelfIdentifier))
        },
        "ThisFieldType" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Keyword(Keyword::ThisFieldType))
        },
        "Null" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Null)
        },
        "Bool" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Bool)
        },
        "Int" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Int)
        },
        "Int32" => {
            check_generics_amount(0, type_item, context);
            preferred_name(
                type_item.identifier_path.identifiers.get(0).unwrap().span,
                "Int", "Int32", context
            );
            Some(Type::Int)
        },
        "Int64" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Int64)
        },
        "Float32" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Float32)
        },
        "Float" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Float)
        },
        "Float64" => {
            check_generics_amount(0, type_item, context);
            preferred_name(
                type_item.identifier_path.identifiers.get(0).unwrap().span,
                "Float", "Float64", context
            );
            Some(Type::Float)
        },
        "Decimal" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Decimal)
        },
        "String" => {
            check_generics_amount(0, type_item, context);
            Some(Type::String)
        },
        "ObjectId" => {
            if availability.contains(Availability::mongo()) {
                check_generics_amount(0, type_item, context);
                Some(Type::ObjectId)
            } else {
                None
            }
        },
        "Date" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Date)
        },
        "DateTime" => {
            check_generics_amount(0, type_item, context);
            Some(Type::DateTime)
        },
        "File" => {
            check_generics_amount(0, type_item, context);
            Some(Type::File)
        },
        "Regex" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Regex)
        },
        "Array" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Array(Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
            }))))
        },
        "Dictionary" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Dictionary(Box::new(type_item.generics.get(1).map_or(Type::Any, |t| {
                resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
            }))))
        },
        "Tuple" => {
            check_generics_amount_more_than_one(type_item, context);
            Some(Type::Tuple(type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect()))
        },
        "Range" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Range(Box::new(type_item.generics.get(0).map_or(Type::Int, |t| {
                let kind = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                if !(kind.is_int_32_or_64() || kind.is_float_32_or_64() || kind.is_decimal()) {
                    context.insert_diagnostics_error(
                        type_item.generics.get(0).unwrap().span(),
                        "range takes number types"
                    );
                    Type::Int
                } else {
                    kind
                }
            }))))
        },
        "Enum" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Enum)
        },
        "Model" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Model)
        },
        "Middleware" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Middleware)
        },
        "DataSet" => {
            check_generics_amount(0, type_item, context);
            Some(Type::DataSet)
        },
        "Namespace" => {
            check_generics_amount(0, type_item, context);
            Some(Type::Namespace)
        }
        "Pipeline" => {
            check_generics_amount(2, type_item, context);
            Some(Type::Pipeline(Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
            })), Box::new(type_item.generics.get(1).map_or(Type::Any, |t| {
                resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
            }))))
        }
        _ => {
            generics_declaration.iter().find_map(|generics_declaration| {
                if generics_declaration.identifiers.iter().find(|i| i.name() == name).is_some() {
                    Some(Type::GenericItem(name.to_string()))
                } else {
                    None
                }
            })
        },
    }
}

// "ModelScalarFields" => {
//     request_single_generics("ModelScalarFields", type_item, context);
//     if let Some(t) = type_item.generics.get(0) {
//         let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
//         if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
//             Some(Type::ModelScalarFields(Box::new(model_object), None))
//         } else {
//             context.insert_diagnostics_error(t.span(), "model not found");
//             Some(Type::Undetermined)
//         }
//     } else {
//         Some(Type::Undetermined)
//     }
// },
// "ModelScalarFieldsWithoutVirtuals" => {
//     request_single_generics("ModelScalarFieldsWithoutVirtuals", type_item, context);
//     if let Some(t) = type_item.generics.get(0) {
//         let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
//         if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
//             Some(Type::ModelScalarFieldsWithoutVirtuals(Box::new(model_object), None))
//         } else {
//             context.insert_diagnostics_error(t.span(), "model not found");
//             Some(Type::Undetermined)
//         }
//     } else {
//         Some(Type::Undetermined)
//     }
// },
// "ModelSerializableScalarFields" => {
//     request_single_generics("ModelSerializableScalarFields", type_item, context);
//     if let Some(t) = type_item.generics.get(0) {
//         let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
//         if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
//             Some(Type::ModelSerializableScalarFields(Box::new(model_object), None))
//         }else {
//             context.insert_diagnostics_error(t.span(), "model not found");
//             Some(Type::Undetermined)
//         }
//     } else {
//         Some(Type::Undetermined)
//     }
// },
// "ModelRelations" => {
//     request_single_generics("ModelRelations", type_item, context);
//     if let Some(t) = type_item.generics.get(0) {
//         let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
//         if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
//             Some(Type::ModelRelations(Box::new(model_object), None))
//         } else {
//             context.insert_diagnostics_error(t.span(), "model not found");
//             Some(Type::Undetermined)
//         }
//     } else {
//         Some(Type::Undetermined)
//     }
// },
// "ModelDirectRelations" => {
//     request_single_generics("ModelDirectRelations", type_item, context);
//     if let Some(t) = type_item.generics.get(0) {
//         let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
//         if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
//             Some(Type::ModelDirectRelations(Box::new(model_object), None))
//         } else {
//             context.insert_diagnostics_error(t.span(), "model not found");
//             Some(Type::Undetermined)
//         }
//     } else {
//         Some(Type::Undetermined)
//     }
// },

fn check_generics_amount<'a>(expect: usize, type_item: &TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generics.len() == expect { return }
    context.insert_diagnostics_error(type_item.identifier_path.span, format!("wrong number of generic arguments, expect {}, found {}", expect, type_item.generics.len()));
}

fn check_generics_amount_multiple<'a>(type_item: &TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generics.len() >= 2 { return }
    context.insert_diagnostics_error(type_item.identifier_path.span, format!("expect multiple generic arguments"));
}

fn check_generics_amount_more_than_one<'a>(type_item: &TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generics.len() >= 1 { return }
    context.insert_diagnostics_error(type_item.identifier_path.span, format!("expect generic arguments"));
}

fn preferred_name<'a>(span: Span, prefer: &str, current: &str, context: &'a ResolverContext<'a>) {
    context.insert_diagnostics_warning(span, format!("prefer '{prefer}' over '{current}'"))
}

