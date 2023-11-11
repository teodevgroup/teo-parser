use crate::ast::argument::Argument;
use crate::ast::argument_declaration::{ArgumentDeclaration, ArgumentListDeclaration};
use crate::ast::argument_list::ArgumentList;
use crate::ast::arith_expr::{ArithExpr, BinaryOperation, UnaryOperation, UnaryPostfixOperation};

#[derive(Debug)]
pub enum Node {
    Argument(Argument),
    ArgumentList(ArgumentList),
    ArgumentListDeclaration(ArgumentListDeclaration),
    ArgumentDeclaration(ArgumentDeclaration),
    ArithExpr(ArithExpr),
    UnaryOperation(UnaryOperation),
    UnaryPostfixOperation(UnaryPostfixOperation),
    BinaryOperation(BinaryOperation),
    // AvailabilityFlag(todo),
    // AvailabilityEndFlag(todo),
}