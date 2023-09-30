use std::cell::RefCell;
use crate::ast::decorator::Decorator;
use crate::ast::decorator_declaration::{DecoratorDeclaration, DecoratorVariant};
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;
use crate::ast::unit::Unit;
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_expression::parse_unit;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_decorator_declaration(pair: Pair<'_>, context: &mut ParserContext) -> DecoratorDeclaration {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut comment = None;
    let mut unique: bool = false;
    let mut model: bool = false;
    let mut r#enum: bool = false;
    let mut interface: bool = false;
    let mut field: bool = false;
    let mut relation: bool = false;
    let mut property: bool = false;
    let mut member: bool = false;
    let mut identifier = None;
    let mut string_path = None;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    let mut variants = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::MODEL_KEYWORD => model = true,
            Rule::ENUM_KEYWORD => r#enum = true,
            Rule::INTERFACE_KEYWORD => interface = true,
            Rule::FIELD_KEYWORD => field = true,
            Rule::RELATION_KEYWORD => relation = true,
            Rule::PROPERTY_KEYWORD => property = true,
            Rule::MEMBER_KEYWORD => member = true,
            Rule::UNIQUE_KEYWORD => unique = true,
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::generics_declaration => generics_declaration = Some(parse_generics_declaration(current, context)),
            Rule::argument_list_declaration => argument_list_declaration = Some(parse_argument_list_declaration(current, context)),
            Rule::generics_constraint => generics_constraint = Some(parse_generics_constraint(current, context)),
            Rule::decorator_variant_declaration => variants.push(parse_decorator_variant_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    DecoratorDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        comment,
        unique,
        decorator_class: parse_decorator_class(model, r#enum, interface, field, relation, property, member, &span, context),
        identifier: identifier.unwrap(),
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        variants,
    }
}

fn parse_decorator_variant_declaration(pair: Pair<'_>, context: &mut ParserContext) -> DecoratorVariant {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::generics_declaration => generics_declaration = Some(parse_generics_declaration(current, context)),
            Rule::argument_list_declaration => argument_list_declaration = Some(parse_argument_list_declaration(current, context)),
            Rule::generics_constraint => generics_constraint = Some(parse_generics_constraint(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    DecoratorVariant {
        span,
        comment,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
    }
}

fn parse_decorator_class(model: bool, r#enum: bool, interface: bool, field: bool, relation: bool, property: bool, member: bool, span: &Span, context: &mut ParserContext) -> ReferenceType {
    if model {
        if field {
            ReferenceType::ModelFieldDecorator
        } else if relation {
            ReferenceType::ModelRelationDecorator
        } else if property {
            ReferenceType::ModelPropertyDecorator
        } else if member {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else {
            ReferenceType::ModelDecorator
        }
    } else if r#enum {
        if field {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else if relation {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else if property {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else if member {
            ReferenceType::EnumMemberDecorator
        } else {
            ReferenceType::EnumDecorator
        }
    } else if interface {
        if field {
            ReferenceType::InterfaceFieldDecorator
        } else if relation {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else if property {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else if member {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceType::Default
        } else {
            ReferenceType::InterfaceDecorator
        }
    } else {
        ReferenceType::Default
    }
}