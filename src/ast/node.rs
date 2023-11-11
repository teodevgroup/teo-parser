use crate::ast::argument::Argument;
use crate::ast::argument_declaration::{ArgumentDeclaration, ArgumentListDeclaration};
use crate::ast::argument_list::ArgumentList;
use crate::ast::arith_expr::{ArithExpr, BinaryOperation, UnaryOperation, UnaryPostfixOperation};
use crate::ast::availability_flag::AvailabilityFlag;
use crate::ast::availability_flag_end::AvailabilityFlagEnd;
use crate::ast::code_comment::CodeComment;
use crate::ast::comment::Comment;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::config_item::ConfigItem;
use crate::ast::constant::Constant;
use crate::ast::data_set::{DataSet, DataSetGroup, DataSetRecord};
use crate::ast::decorator::Decorator;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::expression::Expression;
use crate::ast::field::Field;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsConstraintItem, GenericsDeclaration};
use crate::ast::group::Group;
use crate::ast::handler::{HandlerDeclaration, HandlerGroupDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::import::Import;
use crate::ast::int_subscript::IntSubscript;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::model::Model;
use crate::ast::namespace::Namespace;
use crate::ast::pipeline::Pipeline;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::struct_declaration::StructDeclaration;
use crate::ast::subscript::Subscript;
use crate::ast::type_expr::{TypeBinaryOperation, TypeExpr, TypeGroup, TypeSubscript, TypeTuple};
use crate::ast::unit::Unit;
use crate::ast::use_middlewares::UseMiddlewaresBlock;

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
    AvailabilityFlag(AvailabilityFlag),
    AvailabilityFlagEnd(AvailabilityFlagEnd),
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
    Expression(Expression),
    Group(Group),
    NumericLiteral(NumericLiteral),
    StringLiteral(StringLiteral),
    RegexLiteral(RegexLiteral),
    BoolLiteral(BoolLiteral),
    NullLiteral(NullLiteral),
    EnumVariantLiteral(EnumVariantLiteral),
    TupleLiteral(TupleLiteral),
    ArrayLiteral(ArrayLiteral),
    DictionaryLiteral(DictionaryLiteral),
    Identifier(Identifier),
    Subscript(Subscript),
    IntSubscript(IntSubscript),
    Unit(Unit),
    Pipeline(Pipeline),
    Field(Field),
    FunctionDeclaration(FunctionDeclaration),
    GenericsDeclaration(GenericsDeclaration),
    GenericsConstraint(GenericsConstraint),
    GenericsConstraintItem(GenericsConstraintItem),
    HandlerGroupDeclaration(HandlerGroupDeclaration),
    HandlerDeclaration(HandlerDeclaration),
    IdentifierPath(IdentifierPath),
    Import(Import),
    InterfaceDeclaration(InterfaceDeclaration),
    MiddlewareDeclaration(MiddlewareDeclaration),
    Model(Model),
    Namespace(Namespace),
    PipelineItemDeclaration(PipelineItemDeclaration),
    StructDeclaration(StructDeclaration),
    TypeExpr(TypeExpr),
    TypeBinaryOperation(TypeBinaryOperation),
    TypeGroup(TypeGroup),
    TypeTuple(TypeTuple),
    TypeSubscript(TypeSubscript),
    UseMiddlewareBlock(UseMiddlewaresBlock),
}