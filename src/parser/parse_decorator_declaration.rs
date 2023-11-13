use crate::ast::decorator_declaration::{DecoratorDeclaration, DecoratorDeclarationVariant};
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::{parse_container_node_variables, parse_insert, parse_insert_punctuation, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_decorator_declaration(pair: Pair<'_>, context: &mut ParserContext) -> DecoratorDeclaration {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut exclusive: bool = false;
    let mut unique: bool = false;
    let mut model: bool = false;
    let mut r#enum: bool = false;
    let mut interface: bool = false;
    let mut handler: bool = false;
    let mut field: bool = false;
    let mut relation: bool = false;
    let mut property: bool = false;
    let mut member: bool = false;
    let mut identifier = 0;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    let mut variants = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN => parse_insert_punctuation!(context, current, children, "{"),
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::comment_block => (),
            Rule::triple_comment_block => parse_set_optional!(parse_comment(current, context), children, comment),
            Rule::MODEL_KEYWORD => model = true,
            Rule::ENUM_KEYWORD => r#enum = true,
            Rule::INTERFACE_KEYWORD => interface = true,
            Rule::HANDLER_KEYWORD => handler = true,
            Rule::FIELD_KEYWORD => field = true,
            Rule::RELATION_KEYWORD => relation = true,
            Rule::PROPERTY_KEYWORD => property = true,
            Rule::MEMBER_KEYWORD => member = true,
            Rule::EXCLUSIVE_KEYWORD => exclusive = true,
            Rule::UNIQUE_KEYWORD => unique = true,
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::argument_list_declaration => parse_set_optional!(parse_argument_list_declaration(current, context), children, argument_list_declaration),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            Rule::decorator_variant_declaration => parse_insert!(parse_decorator_variant_declaration(current, context), children, variants),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    DecoratorDeclaration {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        exclusive,
        unique,
        decorator_class: parse_decorator_class(model, r#enum, interface, handler, field, relation, property, member, &span, context),
        comment,
        identifier,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
        variants,
    }
}

fn parse_decorator_variant_declaration(pair: Pair<'_>, context: &mut ParserContext) -> DecoratorDeclarationVariant {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut comment = None;
    let mut generics_declaration = None;
    let mut argument_list_declaration = None;
    let mut generics_constraint = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment_block => parse_set_optional!(parse_comment(current, context), children, comment),
            Rule::generics_declaration => parse_set_optional!(parse_generics_declaration(current, context), children, generics_declaration),
            Rule::argument_list_declaration => parse_set_optional!(parse_argument_list_declaration(current, context), children, argument_list_declaration),
            Rule::generics_constraint => parse_set_optional!(parse_generics_constraint(current, context), children, generics_constraint),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    DecoratorDeclarationVariant {
        span,
        children,
        path,
        comment,
        generics_declaration,
        argument_list_declaration,
        generics_constraint,
    }
}

fn parse_decorator_class(model: bool, r#enum: bool, interface: bool, handler: bool, field: bool, relation: bool, property: bool, member: bool, span: &Span, context: &mut ParserContext) -> ReferenceSpace {
    if model {
        if field {
            ReferenceSpace::ModelFieldDecorator
        } else if relation {
            ReferenceSpace::ModelRelationDecorator
        } else if property {
            ReferenceSpace::ModelPropertyDecorator
        } else if member {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else {
            ReferenceSpace::ModelDecorator
        }
    } else if r#enum {
        if field {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if relation {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if property {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if member {
            ReferenceSpace::EnumMemberDecorator
        } else {
            ReferenceSpace::EnumDecorator
        }
    } else if interface {
        if field {
            ReferenceSpace::InterfaceFieldDecorator
        } else if relation {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if property {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if member {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else {
            ReferenceSpace::InterfaceDecorator
        }
    } else if handler {
        if field {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if relation {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if property {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else if member {
            context.insert_invalid_decorator_declaration(span.clone());
            ReferenceSpace::Default
        } else {
            ReferenceSpace::HandlerDecorator
        }
    } else {
        ReferenceSpace::Default
    }
}