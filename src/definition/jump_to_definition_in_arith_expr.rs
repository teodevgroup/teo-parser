use crate::ast::arith::ArithExpr;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_arith_expr<'a>(
    schema: &'a Schema,
    source: &'a Source,
    arith_expr: &'a ArithExpr,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
) -> Vec<Definition> {
    match arith_expr {
        ArithExpr::Expression(e) => jump_to_definition_in_expression(
            schema,
            source,
            e.as_ref(),
            namespace_path,
            line_col,
            expect,
        ),
        ArithExpr::UnaryPostfixOp(u) => if u.lhs.span().contains_line_col(line_col) {
            jump_to_definition_in_arith_expr(
                schema,
                source,
                u.lhs.as_ref(),
                namespace_path,
                line_col,
                expect
            )
        } else {
            vec![]
        }
        ArithExpr::UnaryOp(u) => if u.rhs.span().contains_line_col(line_col) {
            jump_to_definition_in_arith_expr(
                schema,
                source,
                u.rhs.as_ref(),
                namespace_path,
                line_col,
                expect
            )
        } else {
            vec![]
        }
        ArithExpr::BinaryOp(b) => if b.lhs.span().contains_line_col(line_col) {
            jump_to_definition_in_arith_expr(
                schema,
                source,
                b.lhs.as_ref(),
                namespace_path,
                line_col,
                expect
            )
        } else if b.rhs.span().contains_line_col(line_col) {
            jump_to_definition_in_arith_expr(
                schema,
                source,
                b.rhs.as_ref(),
                namespace_path,
                line_col,
                expect
            )
        } else {
            vec![]
        }
    }
}