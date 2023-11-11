use crate::ast::argument::Argument;
use crate::ast::argument_declaration::{ArgumentDeclaration, ArgumentListDeclaration};
use crate::ast::argument_list::ArgumentList;
use crate::ast::arith_expr::{ArithExpr, BinaryOperation, UnaryOperation, UnaryPostfixOperation};
use crate::ast::code_comment::CodeComment;
use crate::ast::comment::Comment;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::config_item::ConfigItem;
use crate::ast::constant::Constant;
use crate::ast::data_set::{DataSet, DataSetGroup, DataSetRecord};
use crate::ast::decorator::Decorator;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::identifier::Identifier;
use crate::ast::r#enum::{Enum, EnumMember};

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
    CodeComment(CodeComment),
    Comment(Comment),
    Config(Config),
    ConfigItem(ConfigItem),
    ConfigDeclaration(ConfigDeclaration),
    Constant(Constant),
    DataSet(DataSet),
    DataSetGroup(DataSetGroup),
    DataSetRecord(DataSetRecord),
    Decorator(Decorator),
    DecoratorDeclaration(DecoratorDeclaration),
    Enum(Enum),
    EnumMember(EnumMember),

    Identifier(Identifier),

}