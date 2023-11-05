use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_arith_expr::find_completion_in_arith_expr;
use crate::completion::find_completion_in_array_literal::find_completion_in_array_literal;
use crate::completion::find_completion_in_dictionary_literal::find_completion_in_dictionary_literal;
use crate::completion::find_completion_in_enum_variant_literal::find_completion_in_enum_variant_literal;
use crate::completion::find_completion_in_identifier::find_completion_in_identifier;
use crate::completion::find_completion_in_pipeline::find_completion_in_pipeline;
use crate::completion::find_completion_in_tuple_literal::find_completion_in_tuple_literal;
use crate::completion::find_completion_in_unit::find_completion_in_unit;
use crate::r#type::Type;

pub(super) fn find_completion_in_expression(schema: &Schema, source: &Source, expression: &Expression, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    find_completion_in_expression_kind(schema, source, &expression.kind, line_col, namespace_path, expression.resolved().r#type())
}

pub(super) fn find_completion_in_expression_kind(schema: &Schema, source: &Source, kind: &ExpressionKind, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type) -> Vec<CompletionItem> {
    match kind {
        ExpressionKind::Group(g) => find_completion_in_expression(schema, source, g.expression.as_ref(), line_col, namespace_path),
        ExpressionKind::ArithExpr(arith) => find_completion_in_arith_expr(schema, source, arith, line_col, namespace_path),
        ExpressionKind::NumericLiteral(_) => vec![],
        ExpressionKind::StringLiteral(_) => vec![],
        ExpressionKind::RegexLiteral(_) => vec![],
        ExpressionKind::BoolLiteral(_) => vec![],
        ExpressionKind::NullLiteral(_) => vec![],
        ExpressionKind::EnumVariantLiteral(enum_variant_literal) => find_completion_in_enum_variant_literal(schema, source, enum_variant_literal, line_col, namespace_path, expect),
        ExpressionKind::TupleLiteral(tuple) => find_completion_in_tuple_literal(schema, source, tuple, line_col, namespace_path),
        ExpressionKind::ArrayLiteral(array) => find_completion_in_array_literal(schema, source, array, line_col, namespace_path),
        ExpressionKind::DictionaryLiteral(dictionary) => find_completion_in_dictionary_literal(schema, source, dictionary, line_col, namespace_path),
        ExpressionKind::Identifier(identifier) => find_completion_in_identifier(schema, source, identifier, line_col, namespace_path),
        ExpressionKind::ArgumentList(_) => vec![],
        ExpressionKind::Subscript(_) => vec![],
        ExpressionKind::Call(_) => vec![],
        ExpressionKind::Unit(unit) => find_completion_in_unit(schema, source, unit, line_col, namespace_path),
        ExpressionKind::Pipeline(pipeline) => find_completion_in_pipeline(schema, source, pipeline, line_col, namespace_path),
    }
}