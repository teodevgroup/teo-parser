use crate::ast::type_expr::{TypeBinaryOperation, TypeExpr, TypeExprKind, TypeGenerics, TypeGroup, TypeItem, TypeOperator, TypeSubscript, TypeTuple};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule, TYPE_PRATT_PARSER};
use crate::ast::arity::Arity;
use crate::ast::literals::EnumVariantLiteral;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_operator, parse_insert_punctuation, parse_set, parse_set_optional};
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_literals::parse_enum_variant_literal;
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_type_expression(pair: Pair<'_>, context: &mut ParserContext) -> TypeExpr {
    let result = TYPE_PRATT_PARSER.map_primary(|primary| match primary.as_rule() {
        Rule::type_item => TypeExpr::new(TypeExprKind::TypeItem(parse_type_item(primary, context))),
        Rule::type_group => TypeExpr::new(TypeExprKind::TypeGroup(parse_type_group(primary, context))),
        Rule::type_tuple => TypeExpr::new(TypeExprKind::TypeTuple(parse_type_tuple(primary, context))),
        Rule::type_subscript => TypeExpr::new(TypeExprKind::TypeSubscript(parse_type_subscript(primary, context))),
        Rule::type_reference => TypeExpr::new(TypeExprKind::FieldName(parse_type_reference(primary, context))),
        _ => {
            context.insert_unparsed(parse_span(&primary));
            unreachable!()
        },
    }).map_infix(|lhs, operator, rhs| {
        let op = match operator.as_rule() {
            Rule::BI_OR => TypeOperator::BitOr,
            _ => unreachable!(),
        };
        let (span, path, mut children) = parse_container_node_variables!(pair, context);
        let lhs_id = lhs.id();
        let rhs_id = rhs.id();
        children.insert(lhs_id, lhs.into());
        parse_insert_operator!(context, current, children, operator.as_str());
        children.insert(lhs_id, lhs.into());
        let operation = TypeBinaryOperation {
            span,
            children,
            path,
            lhs: lhs_id,
            op,
            rhs: rhs_id,
        };
        parse_container_node_variables_cleanup!(context);
        TypeExpr::new(TypeExprKind::BinaryOp(operation))
    }).parse(pair.into_inner());
    result
}

fn parse_type_item(pair: Pair<'_>, context: &mut ParserContext) -> TypeItem {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut identifier_path = 0;
    let mut generics = None;
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier_path => parse_set!(parse_identifier_path(current, context), children, identifier_path),
            Rule::type_generics => parse_set_optional!(parse_type_generics(current, context), children, generics),
            Rule::arity => if current.as_str() == "[]" {
                arity = Arity::Array;
                parse_insert_punctuation!(context, current, children, "[]");
            } else {
                arity = Arity::Dictionary;
                parse_insert_punctuation!(context, current, children, "{}");
            },
            Rule::OPTIONAL => {
                if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; }
                parse_insert_punctuation!(context, current, children, "?");
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TypeItem {
        span,
        children,
        path,
        identifier_path,
        generics,
        arity,
        item_optional,
        collection_optional,
    }
}

fn parse_type_group(pair: Pair<'_>, context: &mut ParserContext) -> TypeGroup {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut type_expr = 0;
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, type_expr),
            Rule::PAREN_OPEN => parse_insert_punctuation!(context, current, children, "("),
            Rule::PAREN_CLOSE => parse_insert_punctuation!(context, current, children, ")"),
            Rule::arity => if current.as_str() == "[]" {
                arity = Arity::Array;
                parse_insert_punctuation!(context, current, children, "[]");
            } else {
                arity = Arity::Dictionary;
                parse_insert_punctuation!(context, current, children, "{}");
            },
            Rule::OPTIONAL => {
                if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; }
                parse_insert_punctuation!(context, current, children, "?");
            },            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    TypeGroup {
        span,
        children,
        path,
        item_optional,
        arity,
        collection_optional,
        type_expr,
    }
}

fn parse_type_tuple(pair: Pair<'_>, context: &mut ParserContext) -> TypeTuple {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut items = vec![];
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_expression => parse_insert!(parse_type_expression(current, context), children, items),
            Rule::PAREN_OPEN => parse_insert_punctuation!(context, current, children, "("),
            Rule::PAREN_CLOSE => parse_insert_punctuation!(context, current, children, ")"),
            Rule::COMMA => parse_insert_punctuation!(context, current, children, ","),
            Rule::arity => if current.as_str() == "[]" {
                arity = Arity::Array;
                parse_insert_punctuation!(context, current, children, "[]");
            } else {
                arity = Arity::Dictionary;
                parse_insert_punctuation!(context, current, children, "{}");
            },
            Rule::OPTIONAL => {
                if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; }
                parse_insert_punctuation!(context, current, children, "?");
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    TypeTuple {
        span,
        children,
        path,
        items,
        item_optional,
        arity,
        collection_optional,
    }
}

fn parse_type_generics(pair: Pair<'_>, context: &mut ParserContext) -> TypeGenerics {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut type_exprs = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::CHEVRON_OPEN => parse_insert_punctuation!(context, current, children, "<"),
            Rule::CHEVRON_CLOSE => parse_insert_punctuation!(context, current, children, ">"),
            Rule::COMMA => parse_insert_punctuation!(context, current, children, ","),
            Rule::type_expression => parse_insert!(parse_type_expression(current, context), children, type_exprs),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    TypeGenerics {
        span,
        children,
        path,
        type_exprs,
    }
}

fn parse_type_subscript(pair: Pair<'_>, context: &mut ParserContext) -> TypeSubscript {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut container = 0;
    let mut argument = 0;
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BRACKET_OPEN => parse_insert_punctuation!(context, current, children, "["),
            Rule::BRACKET_CLOSE => parse_insert_punctuation!(context, current, children, "]"),
            Rule::type_item => parse_set!(parse_type_item(current, context), children, container),
            Rule::type_expression => parse_set!(parse_type_expression(current, context), children, argument),
            Rule::arity => if current.as_str() == "[]" {
                arity = Arity::Array;
                parse_insert_punctuation!(context, current, children, "[]");
            } else {
                arity = Arity::Dictionary;
                parse_insert_punctuation!(context, current, children, "{}");
            },
            Rule::OPTIONAL => {
                if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; }
                parse_insert_punctuation!(context, current, children, "?");
            },            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    TypeSubscript {
        span,
        children,
        path,
        container,
        argument,
        arity,
        item_optional,
        collection_optional,
    }
}

fn parse_type_reference(pair: Pair<'_>, context: &mut ParserContext) -> EnumVariantLiteral {
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::enum_variant_literal => return parse_enum_variant_literal(current, context),
            _ => unreachable!()
        }
    }
    unreachable!()
}