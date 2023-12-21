use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::handler::{HandlerDeclaration, HandlerGroupDeclaration, HandlerInputFormat};
use crate::ast::model::Model;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::{resolve_type_expr};
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_handler_group_references<'a>(
    handler_group: &'a HandlerGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    if context.has_examined_default_path(&handler_group.string_path, Availability::default()) {
        context.insert_duplicated_identifier(handler_group.identifier().span);
    }
    for handler_declaration in handler_group.handler_declarations() {
        resolve_handler_declaration_types(handler_declaration, context)
    }
    context.add_examined_default_path(handler_group.string_path.clone(), Availability::default());
}

pub(super) fn resolve_handler_group_decorators<'a>(
    handler_group: &'a HandlerGroupDeclaration,
    context: &'a ResolverContext<'a>
) {
    for handler_declaration in handler_group.handler_declarations() {
        resolve_handler_declaration_decorators(handler_declaration, context, None)
    }
}

pub(super) fn resolve_handler_declaration_types<'a>(
    handler_declaration: &'a HandlerDeclaration,
    context: &'a ResolverContext<'a>,
) {
    if context.has_examined_default_path(&handler_declaration.string_path, Availability::default()) {
        context.insert_duplicated_identifier(handler_declaration.identifier().span);
    }
    context.add_examined_default_path(handler_declaration.string_path.clone(), Availability::default());
    if let Some(input_type) = handler_declaration.input_type() {
        resolve_type_expr(input_type, &vec![], &vec![], &btreemap! {}, context, context.current_availability());
    }
    resolve_type_expr(handler_declaration.output_type(), &vec![], &vec![], &btreemap! {}, context, context.current_availability());
    if let Some(input_type) = handler_declaration.input_type() {
        match handler_declaration.input_format {
            HandlerInputFormat::Form => validate_form_type(input_type.resolved(), input_type.span(), context, is_valid_form_input_type),
            HandlerInputFormat::Json => validate_form_type(input_type.resolved(), input_type.span(), context, is_valid_json_input_type),
        }
    }
    validate_form_type(&handler_declaration.output_type().resolved(), handler_declaration.output_type().span(), context, is_valid_json_output_type);
}

pub(super) fn resolve_handler_declaration_decorators<'a>(
    handler_declaration: &'a HandlerDeclaration,
    context: &'a ResolverContext<'a>,
    model: Option<&'a Model>,
) {
    let mut keywords_map = btreemap!{};
    if let Some(model) = model {
        keywords_map.insert(Keyword::SelfIdentifier, Type::ModelObject(Reference::new(model.path.clone(), model.string_path.clone())));
    }
    for decorator in handler_declaration.decorators() {
        resolve_decorator(decorator, context, &keywords_map, ReferenceSpace::HandlerDecorator);
    }
    let is_get_or_delete = if let Some(decorator) = handler_declaration.decorators().find(|d| d.identifier_path().identifiers().last().unwrap().name() == "map") {
        if let Some(argument_list) = decorator.argument_list() {
            if let Some(first_argument) = argument_list.arguments().next() {
                if first_argument.resolved().name.as_str() == "method" {
                    if let Some(value) = first_argument.value().resolved().value() {
                        if let Some(enum_variant) = value.as_enum_variant() {
                            enum_variant.value.as_str() == "get" || enum_variant.value.as_str() == "delete"
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };
    if is_get_or_delete && handler_declaration.input_type().is_some() {
        context.insert_diagnostics_error(handler_declaration.input_type().unwrap().span(), "get or delete handler requires no input type");
    }
    if !is_get_or_delete && handler_declaration.input_type().is_none() {
        context.insert_diagnostics_error(handler_declaration.identifier().span(), "handler requires input type");
    }
}

fn validate_form_type<'a, F>(r#type: &'a Type, span: Span, context: &'a ResolverContext<'a>, f: F) where F: Fn(&Type) -> Option<&'static str> {
    match r#type {
        Type::Any => (),
        Type::SynthesizedShapeReference(shape_reference) => {
            let t = shape_reference.fetch_synthesized_definition(context.schema).unwrap();
            if let Some(shape) = t.as_synthesized_shape() {
                for (_, t) in shape.iter() {
                    if let Some(e) = t.as_enum_variant() {
                        let enum_declaration = context.schema.find_top_by_path(e.path()).unwrap().as_enum().unwrap();
                        if enum_declaration.interface || enum_declaration.option {
                            context.insert_diagnostics_error(span, "interface or option enum is disallowed");
                            break
                        }
                    } else {
                        if let Some(msg) = f(t) {
                            context.insert_diagnostics_error(span, msg);
                            break
                        }
                    }
                }
            } else {
                context.insert_diagnostics_error(span, "handler argument type should be interface or any");
            }
        }
        Type::InterfaceObject(reference, gen) => {
            let interface = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
            let shape = interface.shape_from_generics(gen);
            for (_, t) in shape.iter() {
                if let Some(e) = t.as_enum_variant() {
                    let enum_declaration = context.schema.find_top_by_path(e.path()).unwrap().as_enum().unwrap();
                    if enum_declaration.interface || enum_declaration.option {
                        context.insert_diagnostics_error(span, "interface or option enum is disallowed");
                        break
                    }
                } else {
                    if let Some(msg) = f(t) {
                        context.insert_diagnostics_error(span, msg);
                        break
                    }
                }
            }
        }
        _ => context.insert_diagnostics_error(span, "handler argument type should be interface or any")

    }
}

fn is_valid_form_input_type<'a>(r#type: &'a Type) -> Option<&'static str> {
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
        Type::Dictionary(_) => Some("invalid form handler input type: Dictionary is not supported"),
        Type::Tuple(_) => Some("invalid form handler input type: Tuple is not supported"),
        Type::Range(_) => Some("invalid form handler input type: Range is not supported"),
        Type::Union(_) => Some("invalid form handler input type: Union is not supported"),
        Type::Ignored => None,
        Type::EnumVariant(_) => None,
        Type::Model => Some("invalid form handler input type: Model is not supported"),
        Type::InterfaceObject(_, _items) => None,
        Type::FieldType(_, _) => Some("invalid form handler input type: FieldType is not supported"),
        Type::FieldName(_) => Some("invalid form handler input type: FieldReference is not supported"),
        Type::GenericItem(_) => Some("invalid form handler input type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_form_input_type(inner.as_ref()),
        Type::Undetermined => Some("found unresolved type"),
        Type::ModelObject(_) => Some("invalid form handler input type: Object is not supported"),
        Type::Keyword(_) => Some("found keyword type"),
        Type::Regex => Some("invalid form handler input type: Regex is not supported"),
        Type::StructObject(_, _) => Some("invalid form handler input type: StructObject is not supported"),
        Type::Pipeline(_, _) => Some("invalid form handler input type: Pipeline is not supported"),
        _ => None,
    }
}

fn is_valid_json_input_type<'a>(r#type: &'a Type) -> Option<&'static str> {
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
        Type::File => Some("invalid form handler input type: file is not supported in json input"),
        Type::Array(inner) => is_valid_json_input_type(inner.as_ref()),
        Type::Dictionary(v) => {
            if let Some(msg) = is_valid_json_input_type(v.as_ref()) {
                return Some(msg);
            }
            None
        }
        Type::Tuple(_) => Some("invalid handler input type: Tuple is not supported"),
        Type::Range(_) => Some("invalid handler input type: Range is not supported"),
        Type::Union(_) => Some("invalid handler input type: Union is not supported"),
        Type::Ignored => None,
        Type::EnumVariant(_) => None,
        Type::Model => Some("invalid form handler input type: Model is not supported"),
        Type::InterfaceObject(_, _) => None,
        Type::FieldType(_, _) => Some("invalid handler input type: FieldType is not supported"),
        Type::FieldName(_) => Some("invalid handler input type: FieldReference is not supported"),
        Type::GenericItem(_) => Some("invalid form handler input type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_json_input_type(inner.as_ref()),
        Type::Undetermined => Some("found unresolved type"),
        Type::ModelObject(_) => Some("invalid handler input type: Object is not supported"),
        Type::Keyword(_) => Some("found keyword type"),
        Type::Regex => Some("invalid handler input type: Regex is not supported"),
        Type::StructObject(_, _) => Some("invalid handler input type: StructObject is not supported"),
        Type::Pipeline(_, _) => Some("invalid handler input type: Pipeline is not supported"),
        _ => None,
    }
}

fn is_valid_json_output_type<'a>(r#type: &'a Type) -> Option<&'static str> {
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
        Type::File => Some("invalid form handler output type: file is not supported in json output"),
        Type::Array(inner) => is_valid_json_output_type(inner.as_ref()),
        Type::Dictionary(v) => {
            if let Some(msg) = is_valid_json_output_type(v.as_ref()) {
                return Some(msg);
            }
            None
        }
        Type::Tuple(_) => Some("invalid handler output type: Tuple is not supported"),
        Type::Range(_) => Some("invalid handler output type: Range is not supported"),
        Type::Union(_) => Some("invalid handler output type: Union is not supported"),
        Type::Ignored => None,
        Type::EnumVariant(_) => None,
        Type::Model => Some("invalid form handler output type: Model is not supported"),
        Type::InterfaceObject(_, _) => None,
        Type::FieldType(_, _) => Some("invalid handler output type: FieldType is not supported"),
        Type::FieldName(_) => Some("invalid handler output type: FieldReference is not supported"),
        Type::GenericItem(_) => Some("invalid form handler output type: GenericsItem is not supported"),
        Type::Optional(inner) => is_valid_json_output_type(inner.as_ref()),
        Type::Undetermined => Some("found unresolved type"),
        Type::ModelObject(_) => Some("invalid handler output type: Object is not supported"),
        Type::Keyword(_) => Some("found keyword type"),
        Type::Regex => Some("invalid handler output type: Regex is not supported"),
        Type::StructObject(_, _) => Some("invalid handler output type: StructObject is not supported"),
        Type::Pipeline(_, _) => Some("invalid handler output type: Pipeline is not supported"),
        _ => None,
    }
}
