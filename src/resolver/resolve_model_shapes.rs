use array_tool::vec::Shift;
use indexmap::{IndexMap, indexmap};
use crate::ast::field::Field;
use crate::ast::model::{Model, ModelShapeResolved};
use crate::r#type::Type;
use crate::r#type::model_shape_reference::ModelShapeReference;
use crate::resolver::resolver_context::ResolverContext;
use crate::shape::input::Input;
use crate::shape::shape::Shape;

pub(super) fn resolve_model_shapes<'a>(model: &'a Model, context: &'a ResolverContext<'a>) {
    let mut model_shape_resolved = ModelShapeResolved::new();
    // select
    if let Some(input) = resolve_model_select_shape(model) {
        model_shape_resolved.map.insert("Select".to_owned(), input);
    }
    // include
    if let Some(input) = resolve_model_include_shape(model) {
        model_shape_resolved.map.insert("Include".to_owned(), input);
    }
}

fn resolve_model_select_shape(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(field_settings) = field.resolved().class.as_model_primitive_field() {
            if !field_settings.dropped && !is_field_writeonly(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool));
            }
        } else if let Some(_) = field.resolved().class.as_model_property() {
            if has_property_getter(field) {
                map.insert(field.name().to_owned(), Input::Type(Type::Bool));
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn resolve_model_include_shape(model: &Model) -> Option<Input> {
    let mut map = indexmap! {};
    for field in &model.fields {
        if let Some(relation_settings) = field.resolved().class.as_model_relation() {
            if let Some((related_model_path, related_model_string_path)) = field.type_expr.resolved().unwrap_optional().unwrap_array().as_model_object() {
                if field.type_expr.resolved().unwrap_optional().is_array() {
                    // many
                    map.insert(
                        field.name().to_owned(),
                        Input::Type(Type::ModelShapeReference(ModelShapeReference::FindManyArgs(related_model_path.clone(), related_model_string_path.clone())))
                    );
                } else {
                    // single
                    map.insert(
                        field.name().to_owned(),
                        Input::Type(Type::ModelShapeReference(ModelShapeReference::Args(related_model_path.clone(), related_model_string_path.clone())))
                    );
                }
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Input::Shape(Shape::new(map)))
    }
}

fn has_property_setter(field: &Field) -> bool {
    field_has_decorator_name(field, "setter")
}

fn has_property_getter(field: &Field) -> bool {
    field_has_decorator_name(field, "getter")
}

fn is_field_writeonly(field: &Field) -> bool {
    field_has_decorator_name(field, "writeonly")
}

fn is_field_readonly(field: &Field) -> bool {
    field_has_decorator_name(field, "readonly")
}

fn field_has_decorator_name(field: &Field, name: &str) -> bool {
    field_has_decorator(field, |names| names == vec![name])
}

fn field_has_decorator<F>(field: &Field, f: F) -> bool where F: Fn(Vec<&str>) -> bool {
    for decorator in &field.decorators {
        let names = if *decorator.identifier_path.names().first().unwrap() == "std" {
            let mut result = decorator.identifier_path.names();
            result.shift();
            result
        } else {
            decorator.identifier_path.names()
        };
        if f(names) {
            return true
        }
    }
    false
}