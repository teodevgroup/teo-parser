use maplit::btreemap;
use crate::ast::handler::{HandlerDeclaration, HandlerDeclarationResolved, HandlerGroupDeclaration, HandlerInputFormat};
use crate::ast::reference::ReferenceType;
use crate::ast::type_expr::{TypeShape};
use crate::ast::span::Span;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::{resolve_type_expr, resolve_type_shape};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_handler_group_types<'a>(
    handler_group: &'a HandlerGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    if context.has_examined_default_path(&handler_group.string_path) {
        context.insert_duplicated_identifier(handler_group.identifier.span);
    }
    for handler_declaration in &handler_group.handler_declarations {
        resolve_handler_declaration_types(handler_declaration, context)
    }
}

pub(super) fn resolve_handler_group_decorators<'a>(
    handler_group: &'a HandlerGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    for handler_declaration in &handler_group.handler_declarations {
        resolve_handler_declaration_decorators(handler_declaration, context)
    }
}

pub(super) fn resolve_handler_declaration_types<'a>(
    handler_declaration: &'a HandlerDeclaration,
    context: &'a ResolverContext<'a>,
) {
    if context.has_examined_field(&handler_declaration.identifier.name().to_owned()) {
        context.insert_diagnostics_error(handler_declaration.identifier.span, "DefinitionError: duplicated definition of handler");
    } else {
        context.add_examined_field(handler_declaration.identifier.name.clone());
    }
    resolve_type_expr(&handler_declaration.input_type, &vec![], &vec![], &btreemap! {}, context);
    resolve_type_expr(&handler_declaration.output_type, &vec![], &vec![], &btreemap! {}, context);
    handler_declaration.resolve(HandlerDeclarationResolved {
        input_shape: resolve_type_shape(handler_declaration.input_type.resolved(), context),
        output_shape: resolve_type_shape(handler_declaration.output_type.resolved(), context),
    });
    match handler_declaration.input_format {
        HandlerInputFormat::Form => validate_form_input_type(&handler_declaration.resolved().input_shape, handler_declaration.input_type.span(), context),
        HandlerInputFormat::Json => validate_json_input_type(&handler_declaration.resolved().input_shape, handler_declaration.input_type.span(), context),
    }
    validate_json_output_type(&handler_declaration.resolved().output_shape, handler_declaration.output_type.span(), context);
}

pub(super) fn resolve_handler_declaration_decorators<'a>(
    handler_declaration: &'a HandlerDeclaration,
    context: &'a ResolverContext<'a>,
) {
    for decorator in &handler_declaration.decorators {
        resolve_decorator(decorator, context, &btreemap!{
        }, ReferenceType::HandlerDecorator);
    }
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
        _ => context.insert_diagnostics_error(span, "TypeError: form handler input type should be interface or any")

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
        _ => context.insert_diagnostics_error(span, "TypeError: handler input type should be interface or any")
    }
}

fn is_valid_form_input_shape<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match shape {
        TypeShape::Any => None,
        TypeShape::Type(t) => is_valid_form_input_type(t, context),
        TypeShape::Map(map) => map.values().find_map(|s| is_valid_form_input_shape(s, context)),
        TypeShape::Undetermined => Some("TypeError: handler input type should be interface or any"),
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
        Type::Dictionary(_) => Some("TypeError: invalid form handler input type: Dictionary is not supported"),
        Type::Tuple(_) => Some("TypeError: invalid form handler input type: Tuple is not supported"),
        Type::Range(_) => Some("TypeError: invalid form handler input type: Range is not supported"),
        Type::Union(_) => Some("TypeError: invalid form handler input type: Union is not supported"),
        Type::Ignored => None,
        Type::EnumVariant(path, _) => {
            let r#enum = context.schema.find_top_by_path(path).unwrap().as_enum().unwrap();
            if r#enum.interface {
                Some("TypeError: invalid handler input type: Interface enum is not supported")
            } else if r#enum.option {
                Some("TypeError: invalid handler input type: Option enum is not supported")
            } else {
                None
            }
        }
        Type::Model => Some("TypeError: invalid form handler input type: Model is not supported"),
        Type::InterfaceObject(path, items, _) => None,
        Type::ModelScalarFields(_, _) => Some("TypeError: invalid form handler input type: ModelScalarField is not supported"),
        Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(_, _) => Some("TypeError: invalid form handler input type: ModelScalarFieldAndCachedProperty is not supported"),
        Type::FieldType(_, _) => Some("TypeError: invalid form handler input type: FieldType is not supported"),
        Type::FieldReference(_) => Some("TypeError: invalid form handler input type: FieldReference is not supported"),
        Type::GenericItem(_) => Some("TypeError: invalid form handler input type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_form_input_type(inner.as_ref(), context),
        Type::Undetermined => Some("TypeError: found unresolved type"),
        Type::ModelObject(_, _) => Some("TypeError: invalid form handler input type: Object is not supported"),
        Type::Keyword(_) => Some("TypeError: found keyword type"),
        Type::Regex => Some("TypeError: invalid form handler input type: Regex is not supported"),
        Type::StructObject(_, _) => Some("TypeError: invalid form handler input type: StructObject is not supported"),
        Type::ModelScalarFieldsWithoutVirtuals(_, _) => Some("TypeError: invalid form handler input type: ModelScalarFieldsWithoutVirtuals is not supported"),
        Type::Pipeline(_) => Some("invalid form handler input type: Pipeline is not supported"),
        _ => None,
    }
}

fn is_valid_json_input_shape<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match shape {
        TypeShape::Any => None,
        TypeShape::Type(t) => is_valid_json_input_type(t, context),
        TypeShape::Map(map) => map.values().find_map(|s| is_valid_json_input_shape(s, context)),
        TypeShape::Undetermined => Some("TypeError: handler input type should be interface or any"),
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
        Type::File => Some("TypeError: invalid form handler input type: file is not supported in json input"),
        Type::Array(inner) => is_valid_json_input_type(inner.as_ref(), context),
        Type::Dictionary(v) => {
            if let Some(msg) = is_valid_json_input_type(v.as_ref(), context) {
                return Some(msg);
            }
            None
        }
        Type::Tuple(_) => Some("TypeError: invalid handler input type: Tuple is not supported"),
        Type::Range(_) => Some("TypeError: invalid handler input type: Range is not supported"),
        Type::Union(_) => Some("TypeError: invalid handler input type: Union is not supported"),
        Type::Ignored => None,
        Type::EnumVariant(path, _) => {
            let r#enum = context.schema.find_top_by_path(path).unwrap().as_enum().unwrap();
            if r#enum.interface {
                Some("TypeError: invalid handler input type: Interface enum is not supported")
            } else if r#enum.option {
                Some("TypeError: invalid handler input type: Option enum is not supported")
            } else {
                None
            }
        }
        Type::Model => Some("TypeError: invalid form handler input type: Model is not supported"),
        Type::InterfaceObject(_, _, _) => None,
        Type::ModelScalarFields(_, _) => Some("TypeError: invalid handler input type: ModelScalarField is not supported"),
        Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(_, _) => Some("TypeError: invalid handler input type: ModelScalarFieldAndCachedProperty is not supported"),
        Type::FieldType(_, _) => Some("TypeError: invalid handler input type: FieldType is not supported"),
        Type::FieldReference(_) => Some("TypeError: invalid handler input type: FieldReference is not supported"),
        Type::GenericItem(_) => Some("TypeError: invalid form handler input type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_json_input_type(inner.as_ref(), context),
        Type::Undetermined => Some("TypeError: found unresolved type"),
        Type::ModelObject(_, _) => Some("TypeError: invalid handler input type: Object is not supported"),
        Type::Keyword(_) => Some("TypeError: found keyword type"),
        Type::Regex => Some("TypeError: invalid handler input type: Regex is not supported"),
        Type::StructObject(_, _) => Some("TypeError: invalid handler input type: StructObject is not supported"),
        Type::ModelScalarFieldsWithoutVirtuals(_, _) => Some("TypeError: invalid handler input type: ModelScalarFieldsWithoutVirtuals is not supported"),
        Type::Pipeline(_) => Some("invalid handler input type: Pipeline is not supported"),
        _ => None,
    }
}

fn is_valid_json_output_shape<'a>(shape: &'a TypeShape, context: &'a ResolverContext<'a>) -> Option<&'static str> {
    match shape {
        TypeShape::Any => None,
        TypeShape::Type(t) => is_valid_json_output_type(t, context),
        TypeShape::Map(map) => map.values().find_map(|s| is_valid_json_output_shape(s, context)),
        TypeShape::Undetermined => Some("TypeError: handler output type should be interface or any"),
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
        Type::File => Some("TypeError: invalid form handler output type: file is not supported in json output"),
        Type::Array(inner) => is_valid_json_output_type(inner.as_ref(), context),
        Type::Dictionary(v) => {
            if let Some(msg) = is_valid_json_output_type(v.as_ref(), context) {
                return Some(msg);
            }
            None
        }
        Type::Tuple(_) => Some("TypeError: invalid handler output type: Tuple is not supported"),
        Type::Range(_) => Some("TypeError: invalid handler output type: Range is not supported"),
        Type::Union(_) => Some("TypeError: invalid handler output type: Union is not supported"),
        Type::Ignored => None,
        Type::EnumVariant(path, _) => {
            let r#enum = context.schema.find_top_by_path(path).unwrap().as_enum().unwrap();
            if r#enum.interface {
                Some("TypeError: invalid handler output type: Interface enum is not supported")
            } else if r#enum.option {
                Some("TypeError: invalid handler output type: Option enum is not supported")
            } else {
                None
            }
        }
        Type::Model => Some("TypeError: invalid form handler output type: Model is not supported"),
        Type::InterfaceObject(_, _, _) => None,
        Type::ModelScalarFields(_, _) => Some("TypeError: invalid handler output type: ModelScalarField is not supported"),
        Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(_, _) => Some("TypeError: invalid handler output type: ModelScalarFieldAndCachedProperty is not supported"),
        Type::FieldType(_, _) => Some("TypeError: invalid handler output type: FieldType is not supported"),
        Type::FieldReference(_) => Some("TypeError: invalid handler output type: FieldReference is not supported"),
        Type::GenericItem(_) => Some("TypeError: invalid form handler output type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_json_output_type(inner.as_ref(), context),
        Type::Undetermined => Some("TypeError: found unresolved type"),
        Type::ModelObject(_, _) => Some("TypeError: invalid handler output type: Object is not supported"),
        Type::Keyword(_) => Some("TypeError: found keyword type"),
        Type::Regex => Some("TypeError: invalid handler output type: Regex is not supported"),
        Type::StructObject(_, _) => Some("TypeError: invalid handler output type: StructObject is not supported"),
        Type::ModelScalarFieldsWithoutVirtuals(_, _) => Some("TypeError: invalid handler output type: ModelScalarFieldsWithoutVirtuals is not supported"),
        Type::Pipeline(_) => Some("invalid handler output type: Pipeline is not supported"),
        _ => None,
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
        _ => context.insert_diagnostics_error(span, "TypeError: handler output type should be interface or any")
    }
}