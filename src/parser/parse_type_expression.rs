use std::cell::RefCell;
use crate::ast::r#type::{TypeBinaryOp, TypeExpr, TypeExprKind, TypeItem, TypeOp};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule, TYPE_PRATT_PARSER};

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

}