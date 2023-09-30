use std::cell::RefCell;
use crate::ast::r#type::{TypeBinaryOp, TypeExpr, TypeExprKind, TypeItem, TypeOp};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule, TYPE_PRATT_PARSER};
use crate::ast::arity::Arity;
use crate::parser::parse_identifier_path::parse_identifier_path;

pub(super) fn parse_type_expression(pair: Pair<'_>, context: &mut ParserContext) -> TypeExpr {
    let span = parse_span(&pair);
    let kind = TYPE_PRATT_PARSER.map_primary(|primary| match primary.as_rule() {
        Rule::type_item => TypeExprKind::TypeItem(parse_type_item(primary, context)),
        _ => {
            context.insert_unparsed(parse_span(&primary));
            unreachable!()
        },
    }).map_infix(|lhs, op, rhs| {
        let op = match op.as_rule() {
            Rule::BI_OR => TypeOp::BitOr,
            _ => unreachable!(),
        };
        TypeExprKind::BinaryOp(TypeBinaryOp {
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
    let mut item_required = true;
    let mut arity = Arity::Scalar;
    let mut collection_required = true;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => {},
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::type_generics => generics = parse_type_generics(current, context),
            Rule::arity => if current.as_str() == "[]" { arity = Arity::Array; } else { arity = Arity::Dictionary; },
            Rule::optionality => if arity == Arity::Scalar { item_required = false; } else { collection_required = false; },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TypeItem {
        span,
        identifier_path: identifier_path.unwrap(),
        generics,
        item_required,
        arity,
        collection_required,
    }
}

fn parse_type_generics(pair: Pair<'_>, context: &mut ParserContext) -> Vec<TypeExpr> {
    let mut items = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::type_expression => items.push(parse_type_expression(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    items
}