use std::cell::RefCell;
use crate::ast::type_expr::{TypeBinaryOperation, TypeExpr, TypeExprKind, TypeGroup, TypeItem, TypeOperator, TypeSubscript, TypeTuple};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule, TYPE_PRATT_PARSER};
use crate::ast::arity::Arity;
use crate::ast::literals::EnumVariantLiteral;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_literals::parse_enum_variant_literal;

pub(super) fn parse_type_expression(pair: Pair<'_>, context: &mut ParserContext) -> TypeExpr {
    let span = parse_span(&pair);
    let kind = TYPE_PRATT_PARSER.map_primary(|primary| match primary.as_rule() {
        Rule::type_item => TypeExprKind::TypeItem(parse_type_item(primary, context)),
        Rule::type_group => TypeExprKind::TypeGroup(parse_type_group(primary, context)),
        Rule::type_tuple => TypeExprKind::TypeTuple(parse_type_tuple(primary, context)),
        Rule::type_subscript => TypeExprKind::TypeSubscript(parse_type_subscript(primary, context)),
        Rule::type_reference => TypeExprKind::FieldName(parse_type_reference(primary, context)),
        _ => {
            context.insert_unparsed(parse_span(&primary));
            panic!("unreachable 6")
        },
    }).map_infix(|lhs, op, rhs| {
        let op = match op.as_rule() {
            Rule::BI_OR => TypeOperator::BitOr,
            _ => panic!("unreachable 7"),
        };
        TypeExprKind::BinaryOp(TypeBinaryOperation {
            span,
            lhs: Box::new(lhs),
            op,
            rhs: Box::new(rhs),
        })
    }).parse(pair.into_inner());
    TypeExpr {
        kind,
        resolved: RefCell::new(None),
    }
}

fn parse_type_item(pair: Pair<'_>, context: &mut ParserContext) -> TypeItem {
    let span = parse_span(&pair);
    let mut identifier_path = None;
    let mut generics = vec![];
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => {},
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::type_generics => generics = parse_type_generics(current, context),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::OPTIONAL => if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TypeItem {
        span,
        identifier_path: identifier_path.unwrap(),
        generics,
        item_optional,
        arity,
        collection_optional,
    }
}

fn parse_type_group(pair: Pair<'_>, context: &mut ParserContext) -> TypeGroup {
    let span = parse_span(&pair);
    let mut kind = None;
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;

    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_expression => kind = Some(parse_type_expression(current, context).kind),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::OPTIONAL => if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TypeGroup {
        span,
        kind: Box::new(kind.unwrap()),
        item_optional,
        arity,
        collection_optional,
    }
}

fn parse_type_tuple(pair: Pair<'_>, context: &mut ParserContext) -> TypeTuple {
    let span = parse_span(&pair);
    let mut kinds = vec![];
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;

    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_expression => kinds.push(parse_type_expression(current, context).kind),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::OPTIONAL => if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TypeTuple {
        span,
        items: kinds,
        item_optional,
        arity,
        collection_optional,
    }
}

fn parse_type_generics(pair: Pair<'_>, context: &mut ParserContext) -> Vec<TypeExprKind> {
    let mut items = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_expression => items.push(parse_type_expression(current, context).kind),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    items
}

fn parse_type_subscript(pair: Pair<'_>, context: &mut ParserContext) -> TypeSubscript {
    let span = parse_span(&pair);
    let mut type_item = None;
    let mut type_expr = None;
    let mut item_optional = false;
    let mut arity = Arity::Scalar;
    let mut collection_optional = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_item => type_item = Some(parse_type_item(current, context)),
            Rule::type_expression => type_expr = Some(parse_type_expression(current, context).kind),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::OPTIONAL => if arity == Arity::Scalar { item_optional = true; } else { collection_optional = true; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TypeSubscript {
        span,
        type_item: type_item.unwrap(),
        type_expr: Box::new(type_expr.unwrap()),
        item_optional,
        arity,
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