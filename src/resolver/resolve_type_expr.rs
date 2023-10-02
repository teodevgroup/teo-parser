use crate::ast::arity::Arity;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::r#type::{Type, TypeExpr, TypeExprKind, TypeItem, TypeOp};
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::resolver::resolve_identifier::resolve_identifier_path;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_type_expr<'a>(
    type_expr: &'a TypeExpr,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) {
    type_expr.resolve(
        resolve_type_expr_kind(
            &type_expr.kind,
            generics_declaration,
            generics_constraint,
            context
        )
    )
}

fn resolve_type_expr_kind<'a>(
    type_expr_kind: &'a TypeExprKind,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) -> Type {
    match type_expr_kind {
        TypeExprKind::Expr(expr) => {
            resolve_type_expr_kind(
                expr,
                generics_declaration,
                generics_constraint,
                context
            )
        }
        TypeExprKind::BinaryOp(binaryOp) => {
            match binaryOp.op {
                TypeOp::BitOr => {
                    let lhs = resolve_type_expr_kind(
                        binaryOp.lhs.as_ref(),
                        generics_declaration,
                        generics_constraint,
                        context
                    );
                    let rhs = resolve_type_expr_kind(
                        binaryOp.lhs.as_ref(),
                        generics_declaration,
                        generics_constraint,
                        context
                    );
                    Type::Union(vec![lhs, rhs])
                }
            }
        }
        TypeExprKind::TypeItem(type_item) => {
            resolve_type_item(
                type_item,
                generics_declaration,
                generics_constraint,
                context,
            )
        }
        TypeExprKind::TypeGroup(g) => {
            let resolved = resolve_type_expr_kind(
                g.kind.as_ref(),
                generics_declaration,
                generics_constraint,
                context
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
                context
            )).collect());
            if t.optional {
                Type::Optional(Box::new(resolved))
            } else {
                resolved
            }
        }
    }
}

fn resolve_type_item<'a>(
    type_item: &'a TypeItem,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) -> Type {
    let names = type_item.identifier_path.names();
    let mut base = if names.len() == 1 {
        let name = *names.get(0).unwrap();
        match name {
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
                prefered_name(
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
                prefered_name(
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
            "Array" => {
                request_single_generics("Array", type_item, context);
                Some(Type::Array(Box::new(type_item.generics.get(0).map_or(Type::Any, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context)
                }))))
            },
            "Map" => {
                request_double_generics("Map", type_item, context);
                Some(Type::Dictionary(Box::new(type_item.generics.get(0).map_or(Type::String, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context)
                })), Box::new(type_item.generics.get(1).map_or(Type::Any, |t| {
                    resolve_type_expr_kind(t, generics_declaration, generics_constraint, context)
                }))))
            },
            "Range" => {
                request_single_generics("Range", type_item, context);
                Some(Type::Range(Box::new(type_item.generics.get(0).map_or(Type::Int, |t| {
                    let kind = resolve_type_expr_kind(t, generics_declaration, generics_constraint, context);
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
            "Tuple" => {
                Some(Type::Tuple(type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context)).collect()))
            },
            "Union" => {
                Some(Type::Union(type_item.generics.iter().map(|t| resolve_type_expr_kind(t, generics_declaration, generics_constraint, context)).collect()))
            },
            "Ignored" => {
                Some(Type::Ignored)
            },
            _ => {
                if let Some(generics_declaration) = generics_declaration {
                    if generics_declaration.identifiers.iter().find(|i| i.name() == name).is_some() {
                        Some(Type::GenericItem(name.to_string()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            },
        }
    } else {
        None
    };
    if base.is_none() {
        if let Some(reference) = resolve_identifier_path(&type_item.identifier_path, context, ReferenceType::Default) {
            let top = context.schema.find_top_by_path(&reference.path).unwrap();
            base = match top {
                Top::Model(m) => Some(Type::Model(m.path.clone())),
                Top::Enum(e) => Some(Type::Enum(e.path.clone())),
                Top::Interface(i) => Some(Type::Interface(i.path.clone())),
                _ => None,
            }
        }
        if base.is_none() {
            context.insert_diagnostics_error(type_item.identifier_path.span, "TypeError: Unresolved type");
            base = Some(Type::Unresolved);
        }
    }
    if type_item.item_optional {
        base = Some(Type::Optional(Box::new(base.unwrap())));
    }
    if !type_item.arity.is_scalar() {
        match type_item.arity {
            Arity::Array => base = Some(Type::Array(Box::new(base.unwrap()))),
            Arity::Dictionary => base = Some(Type::Dictionary(Box::new(Type::String), Box::new(base.unwrap()))),
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

fn prefered_name<'a>(span: Span, prefer: &str, current: &str, context: &'a ResolverContext<'a>) {
    context.insert_diagnostics_warning(span, format!("TypeWarning: Prefer '{prefer}' over '{current}'"))
}