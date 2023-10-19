use crate::ast::availability::Availability;
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_arith_expr::jump_to_definition_in_arith_expr;
use crate::definition::jump_to_definition_in_array_literal::jump_to_definition_in_array_literal;
use crate::definition::jump_to_definition_in_dictionary_literal::jump_to_definition_in_dictionary_literal;
use crate::definition::jump_to_definition_in_enum_variant_literal::jump_to_definition_in_enum_variant_literal;
use crate::definition::jump_to_definition_in_identifier::jump_to_definition_in_identifier;
use crate::definition::jump_to_definition_in_pipeline::jump_to_definition_in_pipeline;
use crate::definition::jump_to_definition_in_tuple_literal::jump_to_definition_in_tuple_literal;
use crate::definition::jump_to_definition_in_unit::jump_to_definition_in_unit;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_expression<'a>(
    schema: &'a Schema,
    source: &'a Source,
    expression: &'a Expression,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
    availability: Availability,
) -> Vec<Definition> {
    match &expression.kind {
        ExpressionKind::Group(group) => jump_to_definition_in_expression(
            schema,
            source,
            group.expression.as_ref(),
            namespace_path,
            line_col,
            expect,
            availability
        ),
        ExpressionKind::ArithExpr(arith) => jump_to_definition_in_arith_expr(
            schema,
            source,
            arith,
            namespace_path,
            line_col,
            expect,
            availability,
        ),
        ExpressionKind::NumericLiteral(_) => vec![],
        ExpressionKind::StringLiteral(_) => vec![],
        ExpressionKind::RegexLiteral(_) => vec![],
        ExpressionKind::BoolLiteral(_) => vec![],
        ExpressionKind::NullLiteral(_) => vec![],
        ExpressionKind::EnumVariantLiteral(enum_variant_literal) => jump_to_definition_in_enum_variant_literal(
            schema,
            source,
            enum_variant_literal,
            namespace_path,
            line_col,
            expect,
        ),
        ExpressionKind::TupleLiteral(tuple_literal) => jump_to_definition_in_tuple_literal(
            schema,
            source,
            tuple_literal,
            namespace_path,
            line_col,
            expect,
            availability,
        ),
        ExpressionKind::ArrayLiteral(array_literal) => jump_to_definition_in_array_literal(
            schema,
            source,
            array_literal,
            namespace_path,
            line_col,
            expect,
            availability,
        ),
        ExpressionKind::DictionaryLiteral(dictionary_literal) => jump_to_definition_in_dictionary_literal(
            schema,
            source,
            dictionary_literal,
            namespace_path,
            line_col,
            expect,
            availability,
        ),
        ExpressionKind::Identifier(identifier) => jump_to_definition_in_identifier(
            schema,
            source,
            identifier,
            namespace_path,
            line_col,
            availability,
        ),
        ExpressionKind::ArgumentList(_) => unreachable!(),
        ExpressionKind::Subscript(_) => unreachable!(),
        ExpressionKind::Call(_) => unreachable!(),
        ExpressionKind::Unit(unit) => jump_to_definition_in_unit(
            schema,
            source,
            unit,
            namespace_path,
            line_col,
            expect,
            availability,
        ),
        ExpressionKind::Pipeline(pipeline) => jump_to_definition_in_pipeline(
            schema,
            source,
            pipeline,
            namespace_path,
            line_col,
            availability,
        )
    }
}