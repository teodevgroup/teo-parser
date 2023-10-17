use std::collections::{BTreeMap, HashMap};
use maplit::hashmap;
use crate::ast::arity::Arity;
use crate::ast::availability::Availability;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::type_expr::{TypeExpr, TypeExprKind, TypeItem, TypeOp, TypeShape};
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_identifier::resolve_identifier_path;
use crate::resolver::resolve_type::calculate_generics_map;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_type_expr<'a>(
    type_expr: &'a TypeExpr,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    keywords_map: &BTreeMap<Keyword, &Type>,
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
                TypeOp::BitOr => {
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
            let resolved = resolve_type_expr_kind(
                g.kind.as_ref(),
                generics_declaration,
                generics_constraint,
                context,
                availability,
            );
            if !resolved.is_optional() && g.optional {
                Type::Optional(Box::new(resolved))
            } else {
                resolved
            }
        }
        TypeExprKind::TypeTuple(t) => {
            let resolved = Type::Tuple(t.kinds.iter().map(|k| resolve_type_expr_kind(
                k,
                generics_declaration,
                generics_constraint,
                context,
                availability,
            )).collect());
            if t.optional {
                Type::Optional(Box::new(resolved))
            } else {
                resolved
            }
        }
        TypeExprKind::TypeSubscript(subscript) => {
            let resolved = Type::FieldType(
                Box::new(resolve_type_item(&subscript.type_item, generics_declaration, generics_constraint, context, availability)),
                Box::new(resolve_type_expr_kind(&subscript.type_expr, generics_declaration, generics_constraint, context, availability)),
            );
            if subscript.optional {
                Type::Optional(Box::new(resolved))
            } else {
                resolved
            }
        }
        TypeExprKind::FieldReference(r) => {
            Type::FieldReference(r.identifier.name().to_string())
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
        match name {
            "Ignored" => {
                Some(Type::Ignored)
            },
            "Any" => {
                request_zero_generics("Any", type_item, context);
                Some(Type::Any)
            }
            "Null" => {
                request_zero_generics("Null", type_item, context);
                Some(Type::Null)
            },
            "Bool" => {
                request_zero_generics("Bool", type_item, context);
                Some(Type::Bool)
            },
            "Int" => {
                request_zero_generics("Int", type_item, context);
                Some(Type::Int)
            },
            "Int32" => {
                request_zero_generics("Int", type_item, context);
                preferred_name(
                    type_item.identifier_path.identifiers.get(0).unwrap().span,
                    "Int", "Int32", context
                );
                Some(Type::Int)
            },
            "Int64" => {
                request_zero_generics("Int64", type_item, context);
                Some(Type::Int64)
            },
            "Float32" => {
                request_zero_generics("Float32", type_item, context);
                Some(Type::Float32)
            },
            "Float" => {
                request_zero_generics("Float", type_item, context);
                Some(Type::Float)
            },
            "Float64" => {
                request_zero_generics("Float", type_item, context);
                preferred_name(
                    type_item.identifier_path.identifiers.get(0).unwrap().span,
                    "Float", "Float64", context
                );
                Some(Type::Float)
            },
            "Decimal" => {
                request_zero_generics("Decimal", type_item, context);
                Some(Type::Decimal)
            },
            "String" => {
                request_zero_generics("String", type_item, context);
                Some(Type::String)
            },
            "ObjectId" => {
                request_zero_generics("ObjectId", type_item, context);
                Some(Type::ObjectId)
            },
            "Date" => {
                request_zero_generics("Date", type_item, context);
                Some(Type::Date)
            },
            "DateTime" => {
                request_zero_generics("DateTime", type_item, context);
                Some(Type::DateTime)
            },
            "File" => {
                request_zero_generics("File", type_item, context);
                Some(Type::File)
            },
            "Regex" => {
                request_zero_generics("Regex", type_item, context);
                Some(Type::Regex)
            },
            "Model" => {
                request_zero_generics("Model", type_item, context);
                Some(Type::Model)
            }
            "Array" => {
                request_single_generics("Array", type_item, context);
                Some(Type::Array(Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
                }))))
            },
            "Dictionary" => {
                request_single_generics("Dictionary", type_item, context);
                Some(Type::Dictionary(Box::new(type_item.generics.get(1).map_or(Type::Any, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
                }))))
            },
            "Tuple" => {
                Some(Type::Tuple(type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect()))
            },
            "Range" => {
                request_single_generics("Range", type_item, context);
                Some(Type::Range(Box::new(type_item.generics.get(0).map_or(Type::Int, |t| {
                    let kind = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                    if !(kind.is_int_32_or_64() || kind.is_float_32_or_64()) {
                        context.insert_diagnostics_error(
                            type_item.generics.get(0).unwrap().span(),
                            "TypeError: Range takes integer or floating point number types"
                        );
                        Type::Int
                    } else {
                        kind
                    }
                }))))
            },
            "Union" => {
                Some(Type::Union(type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect()))
            },
            "ModelScalarFields" => {
                request_single_generics("ModelScalarFields", type_item, context);
                if let Some(t) = type_item.generics.get(0) {
                    let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                    if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
                        Some(Type::ModelScalarFields(Box::new(model_object), None))
                    } else {
                        context.insert_diagnostics_error(t.span(), "model not found");
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            },
            "ModelScalarFieldsWithoutVirtuals" => {
                request_single_generics("ModelScalarFieldsWithoutVirtuals", type_item, context);
                if let Some(t) = type_item.generics.get(0) {
                    let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                    if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
                        Some(Type::ModelScalarFieldsWithoutVirtuals(Box::new(model_object), None))
                    } else {
                        context.insert_diagnostics_error(t.span(), "model not found");
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            },
            "ModelScalarFieldsAndCachedPropertiesWithoutVirtuals" => {
                request_single_generics("ModelScalarFieldsAndCachedPropertiesWithoutVirtuals", type_item, context);
                if let Some(t) = type_item.generics.get(0) {
                    let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                    if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
                        Some(Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(Box::new(model_object), None))
                    }else {
                        context.insert_diagnostics_error(t.span(), "model not found");
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            },
            "ModelRelations" => {
                request_single_generics("ModelRelations", type_item, context);
                if let Some(t) = type_item.generics.get(0) {
                    let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                    if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
                        Some(Type::ModelRelations(Box::new(model_object), None))
                    } else {
                        context.insert_diagnostics_error(t.span(), "model not found");
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            },
            "ModelDirectRelations" => {
                request_single_generics("ModelDirectRelations", type_item, context);
                if let Some(t) = type_item.generics.get(0) {
                    let model_object = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                    if model_object.is_model_object() || model_object.is_keyword() || model_object.is_generic_item() {
                        Some(Type::ModelDirectRelations(Box::new(model_object), None))
                    } else {
                        context.insert_diagnostics_error(t.span(), "model not found");
                        Some(Type::Undetermined)
                    }
                } else {
                    Some(Type::Undetermined)
                }
            },
            "FieldType" => {
                request_double_generics("FieldType", type_item, context);
                if type_item.generics.len() != 2 {
                    Some(Type::Undetermined)
                } else {
                    let t = type_item.generics.get(0).unwrap();
                    let f = type_item.generics.get(1).unwrap();
                    if let Some(field_ref) = f.as_field_reference() {
                        let inner_type = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability);
                        if let Some((model_path, _)) = inner_type.as_model_object() {
                            let model = context.schema.find_top_by_path(model_path).unwrap().as_model().unwrap();
                            if let Some(field) = model.fields.iter().find(|f| f.identifier.name() == field_ref.identifier.name()) {
                                Some(field.type_expr.resolved().clone())
                            } else {
                                context.insert_diagnostics_error(f.span(), "field not found");
                                Some(Type::Undetermined)
                            }
                        } else if let Some((interface_path, interface_generics, _)) = inner_type.as_interface_object() {
                            let interface = context.schema.find_top_by_path(interface_path).unwrap().as_interface().unwrap();
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
                    } else {
                        context.insert_diagnostics_error(f.span(), "type is not field reference");
                        Some(Type::Undetermined)
                    }
                }
            },
            "Self" => {
                request_zero_generics("Self", type_item, context);
                Some(Type::Keyword(Keyword::SelfIdentifier))
            },
            "ThisFieldType" => {
                request_zero_generics("ThisFieldType", type_item, context);
                Some(Type::Keyword(Keyword::ThisFieldType))
            },
            "Pipeline" => {
                request_double_generics("Pipeline", type_item, context);
                Some(Type::Pipeline((Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
                })), Box::new(type_item.generics.get(1).map_or(Type::Any, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)
                })))))
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
    } else {
        None
    };
    if base.is_none() {
        if let Some(reference) = resolve_identifier_path(&type_item.identifier_path, context, ReferenceType::Default, availability) {
            let top = context.schema.find_top_by_path(&reference).unwrap();
            base = match top {
                Top::Model(m) => Some(Type::ModelObject(m.path.clone(), m.string_path.clone())),
                Top::Enum(e) => Some(Type::EnumVariant(e.path.clone(), e.string_path.clone())),
                Top::Interface(i) => Some(Type::InterfaceObject(i.path.clone(), type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context, availability)).collect(), i.string_path.clone())),
                Top::StructDeclaration(s) => Some(Type::StructObject(s.path.clone(), s.string_path.clone())),
                _ => None,
            }
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

fn request_zero_generics<'a>(name: &'a str, type_item: &'a TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generics.len() == 0 { return }
    for generic in &type_item.generics {
        context.insert_diagnostics_error(generic.span(), format!("TypeError: {name} doesn't take generics"))
    }
}

fn request_single_generics<'a>(name: &'a str, type_item: &'a TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generics.len() == 1 { return }
    if type_item.generics.len() == 0 {
        context.insert_diagnostics_error(type_item.identifier_path.span, format!("TypeError: {name} takes 1 generics"))
    } else {
        for (index, generic) in type_item.generics.iter().enumerate() {
            if index != 0 {
                context.insert_diagnostics_error(generic.span(), format!("TypeError: Extra generics specified"))
            }
        }
    }
}

fn request_double_generics<'a>(name: &'a str, type_item: &'a TypeItem, context: &'a ResolverContext<'a>) {
    if type_item.generics.len() == 2 { return }
    if type_item.generics.len() < 2 {
        context.insert_diagnostics_error(type_item.identifier_path.span, format!("TypeError: {name} takes 2 generics"))
    } else {
        for (index, generic) in type_item.generics.iter().enumerate() {
            if index >= 2 {
                context.insert_diagnostics_error(generic.span(), format!("TypeError: Extra generics specified"))
            }
        }
    }
}

fn preferred_name<'a>(span: Span, prefer: &str, current: &str, context: &'a ResolverContext<'a>) {
    context.insert_diagnostics_warning(span, format!("TypeWarning: Prefer '{prefer}' over '{current}'"))
}

pub(super) fn resolve_type_shape<'a>(r#type: &Type, context: &'a ResolverContext<'a>) -> TypeShape {
    if r#type.is_any() {
        TypeShape::Any
    } else if r#type.is_ignored() {
        TypeShape::Any
    } else if r#type.is_interface_object() {
        let interface = context.schema.find_top_by_path(r#type.as_interface_object().unwrap().0).unwrap().as_interface().unwrap();
        let generics_map = calculate_generics_map(interface.generics_declaration.as_ref(), r#type.as_interface_object().unwrap().1);
        TypeShape::Map(fetch_all_interface_fields(interface, generics_map, context))
    } else {
        TypeShape::Type(r#type.clone())
    }
}

fn fetch_all_interface_fields<'a>(
    interface: &'a InterfaceDeclaration,
    generics_map: BTreeMap<String, Type>,
    context: &'a ResolverContext<'a>,
) -> HashMap<String, TypeShape> {
    let mut retval = hashmap!{};
    for extend in &interface.extends {
        if extend.resolved().is_interface_object() {
            let interface = context.schema.find_top_by_path(extend.resolved().as_interface_object().unwrap().0).unwrap().as_interface().unwrap();
            let types = extend.resolved().replace_generics(&generics_map);
            let generics_map = calculate_generics_map(interface.generics_declaration.as_ref(), types.as_interface_object().unwrap().1);
            retval.extend(fetch_all_interface_fields(interface, generics_map, context));
        }
    }
    for field in &interface.fields {
        retval.insert(
            field.name().to_owned(),
            resolve_type_shape(&field.type_expr.resolved().replace_generics(&generics_map), context)
        );
    }
    retval
}
