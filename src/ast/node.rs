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

impl Node {

    pub fn is_argument(&self) -> bool {
        self.as_argument().is_some()
    }

    pub fn as_argument(&self) -> Option<&Argument> {
        match self {
            Node::Argument(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_argument_list(&self) -> bool {
        self.as_argument_list().is_some()
    }

    pub fn as_argument_list(&self) -> Option<&ArgumentList> {
        match self {
            Node::ArgumentList(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_argument_list_declaration(&self) -> bool {
        self.as_argument_list_declaration().is_some()
    }

    pub fn as_argument_list_declaration(&self) -> Option<&ArgumentListDeclaration> {
        match self {
            Node::ArgumentListDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_argument_declaration(&self) -> bool {
        self.as_argument_declaration().is_some()
    }

    pub fn as_argument_declaration(&self) -> Option<&ArgumentDeclaration> {
        match self {
            Node::ArgumentDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_arith_expr(&self) -> bool {
        self.as_arith_expr().is_some()
    }

    pub fn as_arith_expr(&self) -> Option<&ArithExpr> {
        match self {
            Node::ArithExpr(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_unary_operation(&self) -> bool {
        self.as_unary_operation().is_some()
    }

    pub fn as_unary_operation(&self) -> Option<&UnaryOperation> {
        match self {
            Node::UnaryOperation(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_unary_postfix_operation(&self) -> bool {
        self.as_unary_postfix_operation().is_some()
    }

    pub fn as_unary_postfix_operation(&self) -> Option<&UnaryPostfixOperation> {
        match self {
            Node::UnaryPostfixOperation(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_binary_operation(&self) -> bool {
        self.as_binary_operation().is_some()
    }

    pub fn as_binary_operation(&self) -> Option<&BinaryOperation> {
        match self {
            Node::BinaryOperation(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_availability_flag(&self) -> bool {
        self.as_availability_flag().is_some()
    }

    pub fn as_availability_flag(&self) -> Option<&AvailabilityFlag> {
        match self {
            Node::AvailabilityFlag(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_availability_flag_end(&self) -> bool {
        self.as_availability_flag_end().is_some()
    }

    pub fn as_availability_flag_end(&self) -> Option<&AvailabilityFlagEnd> {
        match self {
            Node::AvailabilityFlagEnd(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_code_comment(&self) -> bool {
        self.as_code_comment().is_some()
    }

    pub fn as_code_comment(&self) -> Option<&CodeComment> {
        match self {
            Node::CodeComment(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_comment(&self) -> bool {
        self.as_comment().is_some()
    }

    pub fn as_comment(&self) -> Option<&Comment> {
        match self {
            Node::Comment(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_config(&self) -> bool {
        self.as_config().is_some()
    }

    pub fn as_config(&self) -> Option<&Config> {
        match self {
            Node::Config(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_config_item(&self) -> bool {
        self.as_config_item().is_some()
    }

    pub fn as_config_item(&self) -> Option<&ConfigItem> {
        match self {
            Node::ConfigItem(c) => Some(c),
            _ => None,
        }
    }
    
    pub fn is_config_declaration(&self) -> bool {
        self.as_config_declaration().is_some()
    }

    pub fn as_config_declaration(&self) -> Option<&ConfigDeclaration> {
        match self {
            Node::ConfigDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_constant(&self) -> bool {
        self.as_constant().is_some()
    }

    pub fn as_constant(&self) -> Option<&Constant> {
        match self {
            Node::Constant(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_data_set(&self) -> bool {
        self.as_data_set().is_some()
    }

    pub fn as_data_set(&self) -> Option<&DataSet> {
        match self {
            Node::DataSet(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_data_set_group(&self) -> bool {
        self.as_data_set_group().is_some()
    }

    pub fn as_data_set_group(&self) -> Option<&DataSetGroup> {
        match self {
            Node::DataSetGroup(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_data_set_record(&self) -> bool {
        self.as_data_set_record().is_some()
    }

    pub fn as_data_set_record(&self) -> Option<&DataSetRecord> {
        match self {
            Node::DataSetRecord(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_decorator(&self) -> bool {
        self.as_decorator().is_some()
    }

    pub fn as_decorator(&self) -> Option<&Decorator> {
        match self {
            Node::Decorator(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_decorator_declaration(&self) -> bool {
        self.as_decorator_declaration().is_some()
    }

    pub fn as_decorator_declaration(&self) -> Option<&DecoratorDeclaration> {
        match self {
            Node::DecoratorDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_enum(&self) -> bool {
        self.as_enum().is_some()
    }

    pub fn as_enum(&self) -> Option<&Enum> {
        match self {
            Node::Enum(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_enum_member(&self) -> bool {
        self.as_enum_member().is_some()
    }

    pub fn as_enum_member(&self) -> Option<&EnumMember> {
        match self {
            Node::EnumMember(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_expression(&self) -> bool {
        self.as_expression().is_some()
    }

    pub fn as_expression(&self) -> Option<&Expression> {
        match self {
            Node::Expression(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_group(&self) -> bool {
        self.as_group().is_some()
    }

    pub fn as_group(&self) -> Option<&Group> {
        match self {
            Node::Group(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_numeric_literal(&self) -> bool {
        self.as_numeric_literal().is_some()
    }

    pub fn as_numeric_literal(&self) -> Option<&NumericLiteral> {
        match self {
            Node::NumericLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_string_literal(&self) -> bool {
        self.as_string_literal().is_some()
    }

    pub fn as_string_literal(&self) -> Option<&StringLiteral> {
        match self {
            Node::StringLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_regex_literal(&self) -> bool {
        self.as_regex_literal().is_some()
    }

    pub fn as_regex_literal(&self) -> Option<&RegexLiteral> {
        match self {
            Node::RegexLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_bool_literal(&self) -> bool {
        self.as_bool_literal().is_some()
    }

    pub fn as_bool_literal(&self) -> Option<&BoolLiteral> {
        match self {
            Node::BoolLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_null_literal(&self) -> bool {
        self.as_null_literal().is_some()
    }

    pub fn as_null_literal(&self) -> Option<&NullLiteral> {
        match self {
            Node::NullLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_enum_variant_literal(&self) -> bool {
        self.as_enum_variant_literal().is_some()
    }

    pub fn as_enum_variant_literal(&self) -> Option<&EnumVariantLiteral> {
        match self {
            Node::EnumVariantLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_tuple_literal(&self) -> bool {
        self.as_tuple_literal().is_some()
    }

    pub fn as_tuple_literal(&self) -> Option<&TupleLiteral> {
        match self {
            Node::TupleLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_array_literal(&self) -> bool {
        self.as_array_literal().is_some()
    }

    pub fn as_array_literal(&self) -> Option<&ArrayLiteral> {
        match self {
            Node::ArrayLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_dictionary_literal(&self) -> bool {
        self.as_dictionary_literal().is_some()
    }

    pub fn as_dictionary_literal(&self) -> Option<&DictionaryLiteral> {
        match self {
            Node::DictionaryLiteral(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_identifier(&self) -> bool {
        self.as_identifier().is_some()
    }

    pub fn as_identifier(&self) -> Option<&Identifier> {
        match self {
            Node::Identifier(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_subscript(&self) -> bool {
        self.as_subscript().is_some()
    }

    pub fn as_subscript(&self) -> Option<&Subscript> {
        match self {
            Node::Subscript(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_int_subscript(&self) -> bool {
        self.as_int_subscript().is_some()
    }

    pub fn as_int_subscript(&self) -> Option<&IntSubscript> {
        match self {
            Node::IntSubscript(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_unit(&self) -> bool {
        self.as_unit().is_some()
    }

    pub fn as_unit(&self) -> Option<&Unit> {
        match self {
            Node::Unit(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_pipeline(&self) -> bool {
        self.as_pipeline().is_some()
    }

    pub fn as_pipeline(&self) -> Option<&Pipeline> {
        match self {
            Node::Pipeline(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_field(&self) -> bool {
        self.as_field().is_some()
    }

    pub fn as_field(&self) -> Option<&Field> {
        match self {
            Node::Field(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_function_declaration(&self) -> bool {
        self.as_function_declaration().is_some()
    }

    pub fn as_function_declaration(&self) -> Option<&FunctionDeclaration> {
        match self {
            Node::FunctionDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_generics_declaration(&self) -> bool {
        self.as_generics_declaration().is_some()
    }

    pub fn as_generics_declaration(&self) -> Option<&GenericsDeclaration> {
        match self {
            Node::GenericsDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_generics_constraint(&self) -> bool {
        self.as_generics_constraint().is_some()
    }

    pub fn as_generics_constraint(&self) -> Option<&GenericsConstraint> {
        match self {
            Node::GenericsConstraint(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_generics_constraint_item(&self) -> bool {
        self.as_generics_constraint_item().is_some()
    }

    pub fn as_generics_constraint_item(&self) -> Option<&GenericsConstraintItem> {
        match self {
            Node::GenericsConstraintItem(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_handler_group_declaration(&self) -> bool {
        self.as_handler_group_declaration().is_some()
    }

    pub fn as_handler_group_declaration(&self) -> Option<&HandlerGroupDeclaration> {
        match self {
            Node::HandlerGroupDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_handler_declaration(&self) -> bool {
        self.as_handler_declaration().is_some()
    }

    pub fn as_handler_declaration(&self) -> Option<&HandlerDeclaration> {
        match self {
            Node::HandlerDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_identifier_path(&self) -> bool {
        self.as_identifier_path().is_some()
    }

    pub fn as_identifier_path(&self) -> Option<&IdentifierPath> {
        match self {
            Node::IdentifierPath(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_import(&self) -> bool {
        self.as_import().is_some()
    }

    pub fn as_import(&self) -> Option<&Import> {
        match self {
            Node::Import(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_interface_declaration(&self) -> bool {
        self.as_interface_declaration().is_some()
    }

    pub fn as_interface_declaration(&self) -> Option<&InterfaceDeclaration> {
        match self {
            Node::InterfaceDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_middleware_declaration(&self) -> bool {
        self.as_middleware_declaration().is_some()
    }

    pub fn as_middleware_declaration(&self) -> Option<&MiddlewareDeclaration> {
        match self {
            Node::MiddlewareDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_model(&self) -> bool {
        self.as_model().is_some()
    }

    pub fn as_model(&self) -> Option<&Model> {
        match self {
            Node::Model(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_namespace(&self) -> bool {
        self.as_namespace().is_some()
    }

    pub fn as_namespace(&self) -> Option<&Namespace> {
        match self {
            Node::Namespace(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_pipeline_item_declaration(&self) -> bool {
        self.as_pipeline_item_declaration().is_some()
    }

    pub fn as_pipeline_item_declaration(&self) -> Option<&PipelineItemDeclaration> {
        match self {
            Node::PipelineItemDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_struct_declaration(&self) -> bool {
        self.as_struct_declaration().is_some()
    }

    pub fn as_struct_declaration(&self) -> Option<&StructDeclaration> {
        match self {
            Node::StructDeclaration(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_type_expr(&self) -> bool {
        self.as_type_expr().is_some()
    }

    pub fn as_type_expr(&self) -> Option<&TypeExpr> {
        match self {
            Node::TypeExpr(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_type_binary_operation(&self) -> bool {
        self.as_type_binary_operation().is_some()
    }

    pub fn as_type_binary_operation(&self) -> Option<&TypeBinaryOperation> {
        match self {
            Node::TypeBinaryOperation(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_type_group(&self) -> bool {
        self.as_type_group().is_some()
    }

    pub fn as_type_group(&self) -> Option<&TypeGroup> {
        match self {
            Node::TypeGroup(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_type_tuple(&self) -> bool {
        self.as_type_tuple().is_some()
    }

    pub fn as_type_tuple(&self) -> Option<&TypeTuple> {
        match self {
            Node::TypeTuple(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_type_subscript(&self) -> bool {
        self.as_type_subscript().is_some()
    }

    pub fn as_type_subscript(&self) -> Option<&TypeSubscript> {
        match self {
            Node::TypeSubscript(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_use_middleware_block(&self) -> bool {
        self.as_use_middleware_block().is_some()
    }

    pub fn as_use_middleware_block(&self) -> Option<&UseMiddlewaresBlock> {
        match self {
            Node::UseMiddlewareBlock(c) => Some(c),
           _ => None,
        }
    }
}