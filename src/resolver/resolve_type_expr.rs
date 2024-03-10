use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use indexmap::indexmap;
use maplit::{btreemap, btreeset};
use crate::ast::arity::Arity;
use crate::availability::Availability;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::type_expr::{TypeExpr, TypeExprKind, TypeItem, TypeOperator};
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::expr::ReferenceType;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::synthesized_enum::{SynthesizedEnum, SynthesizedEnumMember};
use crate::r#type::synthesized_enum_reference::{SynthesizedEnumReference, SynthesizedEnumReferenceKind};
use crate::r#type::synthesized_interface_enum_reference::{SynthesizedInterfaceEnumReference, SynthesizedInterfaceEnumReferenceKind};
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReferenceKind;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReference;
use crate::resolver::resolve_identifier::resolve_identifier_path;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_type_expr<'a>(
    type_expr: &'a TypeExpr,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    keywords_map: &BTreeMap<Keyword, Type>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) -> Type {
    let result = resolve_type_expr_kind(
        &type_expr.kind,
        generics_declaration,
        generics_constraint,
        keywords_map,
        context,
        availability,
    ).replace_keywords(&keywords_map);
    type_expr.resolve(result.clone());
    result
}

fn resolve_type_expr_kind<'a>(
    type_expr_kind: &'a TypeExprKind,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    keywords_map: &BTreeMap<Keyword, Type>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) -> Type {
    match type_expr_kind {
        TypeExprKind::Expr(expr) => {
            resolve_type_expr_kind(
                expr,
                generics_declaration,
                generics_constraint,
                keywords_map,
                context,
                availability
            )
        }
        TypeExprKind::BinaryOp(binary_op) => {
            match binary_op.op {
                TypeOperator::BitOr => {
                    let lhs = resolve_type_expr(
                        binary_op.lhs(),
                        generics_declaration,
                        generics_constraint,
                        keywords_map,
                        context,
                        availability,
                    );
                    let rhs = resolve_type_expr(
                        binary_op.rhs(),
                        generics_declaration,
                        generics_constraint,
                        keywords_map,
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
                keywords_map,
                context,
                availability,
            )
        }
        TypeExprKind::TypeGroup(g) => {
            let mut resolved = resolve_type_expr(
                g.type_expr(),
                generics_declaration,
                generics_constraint,
                keywords_map,
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
            let mut resolved = Type::Tuple(t.items().map(|k| resolve_type_expr_kind(
                &k.kind,
                generics_declaration,
                generics_constraint,
                keywords_map,
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
                Box::new(resolve_type_expr(subscript.container(), generics_declaration, generics_constraint, keywords_map, context, availability)),
                Box::new(resolve_type_expr(subscript.argument(), generics_declaration, generics_constraint, keywords_map, context, availability)),
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
            Type::FieldName(r.identifier().name().to_string())
        }
        TypeExprKind::TypedShape(typed_shape) => {
            let mut map = indexmap! {};
            let mut used_keys: BTreeSet<&str> = btreeset!{};
            for item in typed_shape.items() {
                if used_keys.contains(&item.identifier().name()) {
                    context.insert_diagnostics_error(item.identifier().span, "duplicated object key");
                } else {
                    resolve_type_expr(item.type_expr(), &vec![], &vec![], &btreemap! {}, context, context.current_availability());
                    if !item.type_expr().resolved().is_undetermined() {
                        map.insert(item.identifier().name().to_owned(), item.type_expr().resolved().clone());
                    }
                    used_keys.insert(item.identifier().name());
                }
            }
            let mut result = Type::SynthesizedShape(SynthesizedShape::new(map));
            if typed_shape.item_optional {
                result = Type::Optional(Box::new(result));
            }
            if !typed_shape.arity.is_scalar() {
                match typed_shape.arity {
                    Arity::Array => result = Type::Array(Box::new(result)),
                    Arity::Dictionary => result = Type::Dictionary(Box::new(result)),
                    _ => ()
                };
                if typed_shape.collection_optional {
                    result = Type::Optional(Box::new(result));
                }
            }
            result
        }
        TypeExprKind::TypedEnum(typed_enum) => {
            let mut members = vec![];
            let mut used_keys: BTreeSet<&str> = btreeset!{};
            for member in typed_enum.members() {
                if used_keys.contains(&member.identifier().name()) {
                    context.insert_diagnostics_error(member.span, "duplicated enum member name");
                } else {
                    members.push(SynthesizedEnumMember {
                        name: member.identifier().name().to_owned(),
                        comment: None,
                    });
                    used_keys.insert(member.identifier().name());
                }
            }
            Type::SynthesizedEnum(SynthesizedEnum::new(members))
        }
    }
}

fn resolve_type_item<'a>(
    type_item: &'a TypeItem,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    keywords_map: &BTreeMap<Keyword, Type>,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) -> Type {
    let names = type_item.identifier_path().names();
    let mut base = if names.len() == 1 {
        let name = *names.get(0).unwrap();
        if let Some(matched) = type_item_builtin_match(name, type_item, generics_declaration, generics_constraint, keywords_map, context, availability) {
            Some(matched)
        } else {
            if let Ok(enum_reference_kind) = SynthesizedEnumReferenceKind::from_str(name) {
                check_generics_amount(1, type_item, context);
                if type_item.generic_items().len() == 1 {
                    let argument = *type_item.generic_items().first().unwrap();
                    let resolved_type = resolve_type_expr(argument, generics_declaration, generics_constraint, keywords_map, context, availability);
                    if resolved_type.is_model_object() || resolved_type.is_keyword() || resolved_type.is_generic_item() {
                        Some(Type::SynthesizedEnumReference(SynthesizedEnumReference {
                            kind: enum_reference_kind,
                            owner: Box::new(resolved_type)
                        }))
                    } else {
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            } else if let Ok(interface_enum_reference_kind) = SynthesizedInterfaceEnumReferenceKind::from_str(name) {
                check_generics_amount(1, type_item, context);
                if type_item.generic_items().len() == 1 {
                    let argument = *type_item.generic_items().first().unwrap();
                    let resolved_type = resolve_type_expr(argument, generics_declaration, generics_constraint, keywords_map, context, availability);
                    if resolved_type.is_model_object() || resolved_type.is_keyword() || resolved_type.is_generic_item() {
                        Some(Type::SynthesizedInterfaceEnumReference(SynthesizedInterfaceEnumReference {
                            kind: interface_enum_reference_kind,
                            owner: Box::new(resolved_type)
                        }))
                    } else {
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            } else if let Ok(shape_reference_kind) = SynthesizedShapeReferenceKind::from_str(name) {
                check_generics_amount(if shape_reference_kind.requires_without() { 2 } else { 1 }, type_item, context);
                if shape_reference_kind.requires_without() && type_item.generic_items().len() == 2 {
                    let argument = *type_item.generic_items().first().unwrap();
                    let without_field_type_expr = *type_item.generic_items().last().unwrap();
                    let resolved_type = resolve_type_expr(argument, generics_declaration, generics_constraint, keywords_map, context, availability);
                    let resolved_field_name = resolve_type_expr(without_field_type_expr, generics_declaration, generics_constraint, keywords_map, context, availability);
                    if (resolved_type.is_model_object() || resolved_type.is_keyword() || resolved_type.is_generic_item()) && resolved_field_name.is_field_name() {
                        let model = context.schema.find_top_by_path(resolved_type.as_model_object().unwrap().path()).unwrap().as_model().unwrap();
                        let found = model.fields().find(|f| f.is_resolved() && f.resolved().class.is_model_primitive_field()).is_some();
                        if found {
                            Some(Type::SynthesizedShapeReference(SynthesizedShapeReference {
                                kind: shape_reference_kind,
                                owner: Box::new(resolved_type),
                                without: Some(resolved_field_name.as_field_name().unwrap().to_owned()),
                            }))
                        } else {
                            Some(Type::Undetermined)
                        }
                    } else {
                        Some(Type::Undetermined)
                    }
                } else if !shape_reference_kind.requires_without() && type_item.generic_items().len() == 1 {
                    let argument = *type_item.generic_items().first().unwrap();
                    let resolved_type = resolve_type_expr(argument, generics_declaration, generics_constraint, keywords_map, context, availability);
                    if resolved_type.is_model_object() {
                        Some(Type::SynthesizedShapeReference(SynthesizedShapeReference {
                            kind: shape_reference_kind,
                            owner: Box::new(resolved_type),
                            without: None,
                        }))
                    } else {
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            } else {
                None
            }
        }
    } else {
        None
    };
    if base.is_none() {
        if let Some(resolved) = resolve_identifier_path(type_item.identifier_path(), context, ReferenceSpace::Default, availability) {
            if let Some(reference_info) = resolved.reference_info() {
                base = match reference_info.r#type() {
                    ReferenceType::Model => Some(Type::ModelObject(reference_info.reference().clone())),
                    ReferenceType::Enum => Some(Type::EnumVariant(reference_info.reference().clone())),
                    ReferenceType::Interface => Some(Type::InterfaceObject(reference_info.reference().clone(), if let Some(generics) = type_item.generics() {
                        generics.type_exprs().map(|t| resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)).collect()
                    } else {
                        vec![]
                    })),
                    ReferenceType::StructDeclaration => Some(Type::StructObject(reference_info.reference().clone(), if let Some(generics) = type_item.generics() {
                        generics.type_exprs().map(|t| resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)).collect()
                    } else {
                        vec![]
                    })),
                    ReferenceType::DeclaredSynthesizedShape => if let Some(generics) = type_item.generics() {
                        let gens: Vec<Type> = generics.type_exprs().map(|t| resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)).collect();
                        if gens.len() == 1 {
                            Some(Type::DeclaredSynthesizedShape(reference_info.reference.clone(), Box::new(gens.get(0).unwrap().clone())))
                        } else {
                            Some(Type::Undetermined)
                        }
                    } else {
                        Some(Type::Undetermined)
                    },
                    _ => None,
                };
            }
        }
        if base.is_none() {
            context.insert_diagnostics_error(type_item.identifier_path().span, "unknown type");
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
    keywords_map: &BTreeMap<Keyword, Type>,
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
            Some(Type::Union(type_item.generic_items().iter().map(|t| resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)).collect()))
        },
        "Enumerable" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Enumerable(Box::new(type_item.generic_items().get(0).map_or(Type::Any, |t| {
                resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)
            }))))
        },
        "Optional" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Optional(Box::new(type_item.generic_items().get(0).map_or(Type::Any, |t| {
                resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)
            }))))
        },
        "FieldType" => {
            check_generics_amount(2, type_item, context);
            if type_item.generic_items().len() != 2 {
                return Some(Type::Undetermined);
            }
            let t = *type_item.generic_items().get(0).unwrap();
            let f = *type_item.generic_items().get(1).unwrap();
            let Some(field_ref) = f.kind.as_field_reference() else {
                context.insert_diagnostics_error(f.span(), "type is not field reference");
                return Some(Type::Undetermined);
            };
            let inner_type = resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability);
            if let Some(reference) = inner_type.as_model_object() {
                let model = context.schema.find_top_by_path(reference.path()).unwrap().as_model().unwrap();
                if let Some(field) = model.fields().find(|f| f.identifier().name() == field_ref.identifier().name()) {
                    Some(field.type_expr().resolved().clone())
                } else {
                    context.insert_diagnostics_error(f.span(), "field not found");
                    Some(Type::Undetermined)
                }
            } else if let Some((reference, interface_generics)) = inner_type.as_interface_object() {
                let interface = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
                let map = interface.calculate_generics_map(interface_generics);
                if let Some(field) = interface.fields().find(|f| f.identifier().name() == field_ref.identifier().name()) {
                    Some(field.type_expr().resolved().replace_generics(&map))
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
                type_item.identifier_path().identifiers().next().unwrap().span,
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
                type_item.identifier_path().identifiers().next().unwrap().span,
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
            Some(Type::Array(Box::new(type_item.generic_items().get(0).map_or(Type::Any, |t| {
                resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)
            }))))
        },
        "Dictionary" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Dictionary(Box::new(type_item.generic_items().get(1).map_or(Type::Any, |t| {
                resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)
            }))))
        },
        "Tuple" => {
            check_generics_amount_more_than_one(type_item, context);
            Some(Type::Tuple(type_item.generic_items().iter().map(|t| resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)).collect()))
        },
        "Range" => {
            check_generics_amount(1, type_item, context);
            Some(Type::Range(Box::new(type_item.generic_items().get(0).map_or(Type::Int, |t| {
                let kind = resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability);
                if !(kind.is_int_32_or_64() || kind.is_float_32_or_64() || kind.is_decimal()) {
                    context.insert_diagnostics_error(
                        type_item.generic_items().get(0).unwrap().span(),
                        "range takes number types"
                    );
                    Type::Int
                } else {
                    kind
                }
            }))))
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
        "Pipeline" => {
            check_generics_amount(2, type_item, context);
            Some(Type::Pipeline(Box::new(type_item.generic_items().get(0).map_or(Type::Any, |t| {
                resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)
            })), Box::new(type_item.generic_items().get(1).map_or(Type::Any, |t| {
                resolve_type_expr(t, generics_declaration, generics_constraint, keywords_map, context, availability)
            }))))
        }
        _ => {
            generics_declaration.iter().find_map(|generics_declaration| {
                if generics_declaration.identifiers().find(|i| i.name() == name).is_some() {
                    Some(Type::GenericItem(name.to_string()))
                } else {
                    None
                }
            })
        },
    }
}

fn check_generics_amount<'a>(expect: usize, type_item: &TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generic_items().len() == expect { return }
    context.insert_diagnostics_error(type_item.identifier_path().span, format!("wrong number of generic arguments, expect {}, found {}", expect, type_item.generic_items().len()));
}

fn check_generics_amount_multiple<'a>(type_item: &TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generic_items().len() >= 2 { return }
    context.insert_diagnostics_error(type_item.identifier_path().span, format!("expect multiple generic arguments"));
}

fn check_generics_amount_more_than_one<'a>(type_item: &TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generic_items().len() >= 1 { return }
    context.insert_diagnostics_error(type_item.identifier_path().span, format!("expect generic arguments"));
}

fn preferred_name<'a>(span: Span, prefer: &str, current: &str, context: &'a ResolverContext<'a>) {
    context.insert_diagnostics_warning(span, format!("prefer '{prefer}' over '{current}'"))
}

