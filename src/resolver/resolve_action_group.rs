use crate::ast::action::{ActionDeclaration, ActionDeclarationResolved, ActionGroupDeclaration, ActionInputFormat};
use crate::ast::r#type::{Type, TypeExpr, TypeShape};
use crate::ast::span::Span;
use crate::resolver::resolve_type_expr::{resolve_type_expr, resolve_type_shape};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_action_group<'a>(
    action_group: &'a ActionGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    for action_declaration in &action_group.action_declarations {
        resolve_action_declaration(action_declaration, context)
    }
}

pub(super) fn resolve_action_declaration<'a>(
    action_declaration: &'a ActionDeclaration,
    context: &'a ResolverContext<'a>,
) {
    if context.has_examined_action_path(&action_declaration.string_path) {
        context.insert_diagnostics_error(action_declaration.identifier.span, "DefinitionError: duplicated definition of action");
    } else {
        context.add_examined_action_path(action_declaration.string_path.clone());
    }
    resolve_type_expr(&action_declaration.input_type, None, None, context);
    resolve_type_expr(&action_declaration.output_type, None, None, context);
    action_declaration.resolve(ActionDeclarationResolved {
        input_shape: resolve_type_shape(action_declaration.input_type.resolved(), context),
        output_shape: resolve_type_shape(action_declaration.output_type.resolved(), context),
    });
    match action_declaration.input_format {
        ActionInputFormat::Form => validate_form_input_type(&action_declaration.resolved().input_shape, action_declaration.input_type.span(), context),
        ActionInputFormat::Json => validate_json_input_type(&action_declaration.resolved().input_shape, action_declaration.input_type.span(), context),
    }
    validate_json_output_type(&action_declaration.resolved().output_shape, action_declaration.output_type.span(), context);
}

fn validate_form_input_type<'a>(shape: &'a TypeShape, span: Span, context: &'a ResolverContext<'a>) {
    match shape {
        TypeShape::Any => (),
        TypeShape::Map(map) => {
            for r#type in map.values() {
                if let Some(msg) = is_valid_form_input_shape(r#type, context) {
                    context.insert_diagnostics_error(span, msg);
                    return
                }
            }
        }
        _ => context.insert_diagnostics_error(span, "TypeError: form action input type should be interface or any")

    }
}

fn validate_json_input_type<'a>(shape: &'a TypeShape, span: Span, context: &'a ResolverContext<'a>) {
    match shape {
        TypeShape::Any => (),
        TypeShape::Map(map) => {
            for r#type in map.values() {
                if let Some(msg) = is_valid_json_input_shape(r#type, context) {
                    context.insert_diagnostics_error(span, msg);
                    return
                }
            }
        }
        _ => context.insert_diagnostics_error(span, "TypeError: action input type should be interface or any")
    }
}

fn is_valid_form_input_shape<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match shape {
        TypeShape::Any => None,
        TypeShape::Type(t) => is_valid_form_input_type(t, context),
        TypeShape::Map(map) => map.values().find_map(|s| is_valid_form_input_shape(s, context)),
        TypeShape::Undetermined => Some("TypeError: action input type should be interface or any"),
    }
}

fn is_valid_form_input_type<'a>(r#type: &'a Type, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match r#type {
        Type::Any => None,
        Type::Null => None,
        Type::Bool => None,
        Type::Int => None,
        Type::Int64 => None,
        Type::Float32 => None,
        Type::Float => None,
        Type::Decimal => None,
        Type::String => None,
        Type::ObjectId => None,
        Type::Date => None,
        Type::DateTime => None,
        Type::File => None,
        Type::Array(_) => None,
        Type::Dictionary(_, _) => Some("TypeError: invalid form action input type: Dictionary is not supported"),
        Type::Tuple(_) => Some("TypeError: invalid form action input type: Tuple is not supported"),
        Type::Range(_) => Some("TypeError: invalid form action input type: Range is not supported"),
        Type::Union(_) => Some("TypeError: invalid form action input type: Union is not supported"),
        Type::Ignored => None,
        Type::Enum(path) => {
            let r#enum = context.schema.find_top_by_path(path).unwrap().as_enum().unwrap();
            if r#enum.interface {
                Some("TypeError: invalid action input type: Interface enum is not supported")
            } else if r#enum.option {
                Some("TypeError: invalid action input type: Option enum is not supported")
            } else {
                None
            }
        }
        Type::Model(_) => Some("TypeError: invalid form action input type: Model is not supported"),
        Type::Interface(path, items) => None,
        Type::ModelScalarField(_) => Some("TypeError: invalid form action input type: ModelScalarField is not supported"),
        Type::ModelScalarFieldAndCachedProperty(_) => Some("TypeError: invalid form action input type: ModelScalarFieldAndCachedProperty is not supported"),
        Type::FieldType(_, _) => Some("TypeError: invalid form action input type: FieldType is not supported"),
        Type::GenericItem(_) => Some("TypeError: invalid form action input type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_form_input_type(inner.as_ref(), context),
        Type::Unresolved => Some("TypeError: found unresolved type"),
    }
}

fn is_valid_json_input_shape<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match shape {
        TypeShape::Any => None,
        TypeShape::Type(t) => is_valid_json_input_type(t, context),
        TypeShape::Map(map) => map.values().find_map(|s| is_valid_json_input_shape(s, context)),
        TypeShape::Undetermined => Some("TypeError: action input type should be interface or any"),
    }
}

fn is_valid_json_input_type<'a>(r#type: &'a Type, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match r#type {
        Type::Any => None,
        Type::Null => None,
        Type::Bool => None,
        Type::Int => None,
        Type::Int64 => None,
        Type::Float32 => None,
        Type::Float => None,
        Type::Decimal => None,
        Type::String => None,
        Type::ObjectId => None,
        Type::Date => None,
        Type::DateTime => None,
        Type::File => Some("TypeError: invalid form action input type: file is not supported in json input"),
        Type::Array(inner) => is_valid_json_input_type(inner.as_ref(), context),
        Type::Dictionary(k, v) => {
            if let Some(msg) = is_valid_json_input_type(k.as_ref(), context) {
                return Some(msg);
            }
            if let Some(msg) = is_valid_json_input_type(v.as_ref(), context) {
                return Some(msg);
            }
            None
        }
        Type::Tuple(_) => Some("TypeError: invalid action input type: Tuple is not supported"),
        Type::Range(_) => Some("TypeError: invalid action input type: Range is not supported"),
        Type::Union(_) => Some("TypeError: invalid action input type: Union is not supported"),
        Type::Ignored => None,
        Type::Enum(path) => {
            let r#enum = context.schema.find_top_by_path(path).unwrap().as_enum().unwrap();
            if r#enum.interface {
                Some("TypeError: invalid action input type: Interface enum is not supported")
            } else if r#enum.option {
                Some("TypeError: invalid action input type: Option enum is not supported")
            } else {
                None
            }
        }
        Type::Model(_) => Some("TypeError: invalid form action input type: Model is not supported"),
        Type::Interface(_, __) => None,
        Type::ModelScalarField(_) => Some("TypeError: invalid action input type: ModelScalarField is not supported"),
        Type::ModelScalarFieldAndCachedProperty(_) => Some("TypeError: invalid action input type: ModelScalarFieldAndCachedProperty is not supported"),
        Type::FieldType(_, _) => Some("TypeError: invalid action input type: FieldType is not supported"),
        Type::GenericItem(_) => Some("TypeError: invalid form action input type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_json_input_type(inner.as_ref(), context),
        Type::Unresolved => Some("TypeError: found unresolved type"),
    }
}

fn is_valid_json_output_shape<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match shape {
        TypeShape::Any => None,
        TypeShape::Type(t) => is_valid_json_output_type(t, context),
        TypeShape::Map(map) => map.values().find_map(|s| is_valid_json_output_shape(s, context)),
        TypeShape::Undetermined => Some("TypeError: action output type should be interface or any"),
    }
}

fn is_valid_json_output_type<'a>(r#type: &'a Type, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match r#type {
        Type::Any => None,
        Type::Null => None,
        Type::Bool => None,
        Type::Int => None,
        Type::Int64 => None,
        Type::Float32 => None,
        Type::Float => None,
        Type::Decimal => None,
        Type::String => None,
        Type::ObjectId => None,
        Type::Date => None,
        Type::DateTime => None,
        Type::File => Some("TypeError: invalid form action output type: file is not supported in json output"),
        Type::Array(inner) => is_valid_json_output_type(inner.as_ref(), context),
        Type::Dictionary(k, v) => {
            if let Some(msg) = is_valid_json_output_type(k.as_ref(), context) {
                return Some(msg);
            }
            if let Some(msg) = is_valid_json_output_type(v.as_ref(), context) {
                return Some(msg);
            }
            None
        }
        Type::Tuple(_) => Some("TypeError: invalid action output type: Tuple is not supported"),
        Type::Range(_) => Some("TypeError: invalid action output type: Range is not supported"),
        Type::Union(_) => Some("TypeError: invalid action output type: Union is not supported"),
        Type::Ignored => None,
        Type::Enum(path) => {
            let r#enum = context.schema.find_top_by_path(path).unwrap().as_enum().unwrap();
            if r#enum.interface {
                Some("TypeError: invalid action output type: Interface enum is not supported")
            } else if r#enum.option {
                Some("TypeError: invalid action output type: Option enum is not supported")
            } else {
                None
            }
        }
        Type::Model(_) => Some("TypeError: invalid form action output type: Model is not supported"),
        Type::Interface(_, __) => None,
        Type::ModelScalarField(_) => Some("TypeError: invalid action output type: ModelScalarField is not supported"),
        Type::ModelScalarFieldAndCachedProperty(_) => Some("TypeError: invalid action output type: ModelScalarFieldAndCachedProperty is not supported"),
        Type::FieldType(_, _) => Some("TypeError: invalid action output type: FieldType is not supported"),
        Type::GenericItem(_) => Some("TypeError: invalid form action output type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_json_output_type(inner.as_ref(), context),
        Type::Unresolved => Some("TypeError: found unresolved type"),
    }
}


fn validate_json_output_type<'a>(shape: &'a TypeShape, span: Span, context: &'a ResolverContext<'a>) {
    match shape {
        TypeShape::Any => (),
        TypeShape::Map(map) => {
            for r#type in map.values() {
                if let Some(msg) = is_valid_json_output_shape(r#type, context) {
                    context.insert_diagnostics_error(span, msg);
                    return
                }
            }
        }
        _ => context.insert_diagnostics_error(span, "TypeError: action output type should be interface or any")
    }
}