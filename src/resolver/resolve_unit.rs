use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression_kind;
use crate::resolver::resolver_context::ResolverContext;

pub(super) enum UnitResolveResult {
    Reference(Vec<usize>),
    Type(Type),
}

impl UnitResolveResult {

    pub(super) fn is_reference(&self) -> bool {
        self.as_reference().is_some()
    }

    pub(super) fn as_reference(&self) -> Option<&Vec<usize>> {
        match self {
            Self::Reference(r) => Some(r),
            _ => None,
        }
    }

    pub(super) fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub(super) fn as_type(&self) -> Option<&Type> {
        match self {
            Self::Type(t) => Some(t),
            _ => None,
        }
    }
}

pub(super) fn resolve_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    if unit.expressions.len() == 1 {
        resolve_expression_kind(unit.expressions.get(0).unwrap(), context, expected)
    } else {
        let expected = Type::Undetermined;
        let mut current = resolve_expression_kind(unit.expressions.get(0).unwrap(), context, &expected);
        if current.is_undetermined() {
            return current;
        } else {
            for (index, item) in unit.expressions.iter().enumerate() {
                if index == 0 { continue }
                current = resolve_current_item_for_unit(&current, item, context);
            }
            current
        }
    }
}

fn resolve_current_item_for_unit<'a>(current: &Accessible, item: &ExpressionKind, context: &'a ResolverContext<'a>) -> Accessible {
    match current {
        Accessible::Type(current_value) => {
            context.insert_diagnostics_error(item.span(), "Builtin instance fields and methods are not implemented yet");
            Accessible::Type(Type::Undetermined)

            // if current_value.is_reference() {
            //     resolve_current_item_for_unit(&Accessible::Reference(Reference {
            //         path: current_value.as_reference().unwrap().clone(),
            //         r#type: ReferenceType::Default,
            //     }), item, context)
            // } else {
            // }
        }
        Accessible::Reference(current_reference) => {
            match context.schema.find_top_by_path(&current_reference.path).unwrap() {
                Top::Config(config) => {
                    match item {
                        ExpressionKind::Identifier(identifier) => {
                            if let Some(item) = config.items.iter().find(|i| i.identifier.name() == identifier.name()) {
                                return item.expression.resolved().clone();
                            } else {
                                context.insert_diagnostics_error(item.span(), "Undefined field");
                                return Accessible::Type(Type::Undetermined)
                            }
                        },
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Config cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Config cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Config cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Constant(constant) => {
                    if !constant.is_resolved() {
                        resolve_constant(constant, context);
                    }
                    resolve_current_item_for_unit(&Accessible::Type(track_accessible_upwards(&current, context)), item, context)
                }
                Top::Enum(r#enum) => {
                    match item {
                        ExpressionKind::Identifier(i) => {
                            return Accessible::Type(resolve_enum_variant_literal(&EnumVariantLiteral {
                                span: Span::default(),
                                identifier: i.clone(),
                                argument_list: None,
                            }, context, &Type::Enum(r#enum.path.clone())))
                        }
                        ExpressionKind::Call(c) => {
                            return Accessible::Type(resolve_enum_variant_literal(&EnumVariantLiteral {
                                span: Span::default(),
                                identifier: c.identifier.clone(),
                                argument_list: None,
                            }, context, &Type::Enum(r#enum.path.clone())))
                        }
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Enum cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Enum cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Model(_) => {
                    match item {
                        ExpressionKind::Identifier(_) => todo!("return model field enum here"),
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Model cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Model cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Model cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Interface(_) => {
                    match item {
                        ExpressionKind::Identifier(_) => todo!("return interface field enum here"),
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Interface cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Interface cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Interface cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Namespace(namespace) => {
                    match item {
                        ExpressionKind::Identifier(identifier) => {
                            if let Some(top) = namespace.find_top_by_name(identifier.name(), &top_filter_for_reference_type(ReferenceType::Default)) {
                                return Accessible::Reference(Reference {
                                    path: top.path().clone(),
                                    r#type: ReferenceType::Default,
                                })
                            } else {
                                context.insert_diagnostics_error(identifier.span, "Invalid reference");
                                return Accessible::Type(Type::Undetermined)
                            }
                        },
                        ExpressionKind::Call(c) => {
                            todo!("resolve and call")
                        }
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Namespace cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Namespace cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                _ => unreachable!()
            }
        }
    }
}

