use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::ast::argument::Argument;
use crate::ast::argument_declaration::{ArgumentDeclaration};
use crate::ast::argument_list::ArgumentList;
use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::ast::arith_expr::{ArithExpr, BinaryOperation, UnaryOperation, UnaryPostfixOperation};
use crate::ast::availability_flag::AvailabilityFlag;
use crate::ast::availability_flag_end::AvailabilityFlagEnd;
use crate::ast::code_comment::CodeComment;
use crate::ast::doc_comment::DocComment;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::config_item::ConfigItem;
use crate::ast::keyword::Keyword;
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
use crate::ast::operators::Operator;
use crate::ast::pipeline::Pipeline;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::punctuations::Punctuation;
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::span::Span;
use crate::ast::struct_declaration::StructDeclaration;
use crate::ast::subscript::Subscript;
use crate::ast::type_expr::{TypeBinaryOperation, TypeExpr, TypeGroup, TypeSubscript, TypeTuple};
use crate::ast::unit::Unit;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::availability::Availability;
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::write::Write;

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
    DocComment(DocComment),
    Config(Config),
    Keyword(Keyword),
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
    Punctuation(Punctuation),
    Operator(Operator),
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

    pub fn is_doc_comment(&self) -> bool {
        self.as_doc_comment().is_some()
    }

    pub fn as_doc_comment(&self) -> Option<&DocComment> {
        match self {
            Node::DocComment(c) => Some(c),
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

    pub fn is_keyword(&self) -> bool {
        self.as_keyword().is_some()
    }

    pub fn as_keyword(&self) -> Option<&Keyword> {
        match self {
            Node::Keyword(c) => Some(c),
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

    pub fn is_punctuation(&self) -> bool {
        self.as_punctuation().is_some()
    }

    pub fn as_punctuation(&self) -> Option<&Punctuation> {
        match self {
            Node::Punctuation(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_operator(&self) -> bool {
        self.as_operator().is_some()
    }

    pub fn as_operator(&self) -> Option<&Operator> {
        match self {
            Node::Operator(c) => Some(c),
            _ => None,
        }
    }

    pub fn as_dyn_node_trait(&self) -> &dyn NodeTrait {
        match self {
            Node::Argument(n) => n,
            Node::ArgumentList(n) => n,
            Node::ArgumentListDeclaration(n) => n,
            Node::ArgumentDeclaration(n) => n,
            Node::ArithExpr(n) => n,
            Node::UnaryOperation(n) => n,
            Node::UnaryPostfixOperation(n) => n,
            Node::BinaryOperation(n) => n,
            Node::AvailabilityFlag(n) => n,
            Node::AvailabilityFlagEnd(n) => n,
            Node::CodeComment(n) => n,
            Node::DocComment(n) => n,
            Node::Config(n) => n,
            Node::Keyword(n) => n,
            Node::ConfigItem(n) => n,
            Node::ConfigDeclaration(n) => n,
            Node::Constant(n) => n,
            Node::DataSet(n) => n,
            Node::DataSetGroup(n) => n,
            Node::DataSetRecord(n) => n,
            Node::Decorator(n) => n,
            Node::DecoratorDeclaration(n) => n,
            Node::Enum(n) => n,
            Node::EnumMember(n) => n,
            Node::Expression(n) => n,
            Node::Group(n) => n,
            Node::NumericLiteral(n) => n,
            Node::StringLiteral(n) => n,
            Node::RegexLiteral(n) => n,
            Node::BoolLiteral(n) => n,
            Node::NullLiteral(n) => n,
            Node::EnumVariantLiteral(n) => n,
            Node::TupleLiteral(n) => n,
            Node::ArrayLiteral(n) => n,
            Node::DictionaryLiteral(n) => n,
            Node::Identifier(n) => n,
            Node::Subscript(n) => n,
            Node::IntSubscript(n) => n,
            Node::Unit(n) => n,
            Node::Pipeline(n) => n,
            Node::Field(n) => n,
            Node::FunctionDeclaration(n) => n,
            Node::GenericsDeclaration(n) => n,
            Node::GenericsConstraint(n) => n,
            Node::GenericsConstraintItem(n) => n,
            Node::HandlerGroupDeclaration(n) => n,
            Node::HandlerDeclaration(n) => n,
            Node::IdentifierPath(n) => n,
            Node::Import(n) => n,
            Node::InterfaceDeclaration(n) => n,
            Node::MiddlewareDeclaration(n) => n,
            Node::Model(n) => n,
            Node::Namespace(n) => n,
            Node::PipelineItemDeclaration(n) => n,
            Node::StructDeclaration(n) => n,
            Node::TypeExpr(n) => n,
            Node::TypeBinaryOperation(n) => n,
            Node::TypeGroup(n) => n,
            Node::TypeTuple(n) => n,
            Node::TypeSubscript(n) => n,
            Node::UseMiddlewareBlock(n) => n,
            Node::Punctuation(n) => n,
            Node::Operator(n) => n,
        }
    }

    pub fn identifier_span(&self) -> Option<Span> {
        match self {
            Node::Constant(c) => Some(c.identifier().span()),
            Node::Enum(e) => Some(e.identifier().span()),
            Node::Model(m) => Some(m.identifier().span()),
            Node::Config(c) => Some(c.identifier().as_ref().map_or(c.keyword().span(), |i| i.span())),
            Node::ConfigDeclaration(c) => Some(c.identifier().span()),
            Node::DataSet(d) => Some(d.identifier().span()),
            Node::MiddlewareDeclaration(m) => Some(m.identifier().span()),
            Node::HandlerGroupDeclaration(a) => Some(a.identifier().span()),
            Node::InterfaceDeclaration(i) => Some(i.identifier().span()),
            Node::Namespace(n) => Some(n.identifier().span()),
            Node::DecoratorDeclaration(d) => Some(d.identifier().span()),
            Node::PipelineItemDeclaration(p) => Some(p.identifier().span()),
            Node::StructDeclaration(s) => Some(s.identifier().span()),
            _ => None,
        }
    }

    pub fn available_test(&self, availability: Availability) -> bool {
        match self {
            Node::Constant(t) => t.define_availability().contains(availability),
            Node::Enum(t) => t.define_availability().contains(availability),
            Node::Model(t) => t.define_availability().contains(availability),
            Node::DataSet(t) => t.define_availability().contains(availability),
            Node::InterfaceDeclaration(t) => t.define_availability().contains(availability),
            Node::DecoratorDeclaration(t) => t.define_availability().contains(availability),
            Node::PipelineItemDeclaration(t) => t.define_availability().contains(availability),
            Node::StructDeclaration(t) => t.define_availability().contains(availability),
            _ => true,
        }
    }

    pub fn string_path(&self) -> Option<&Vec<String>> {
        match self {
            Node::Constant(c) => Some(c.string_path()),
            Node::Enum(e) => Some(e.string_path()),
            Node::Model(m) => Some(m.string_path()),
            Node::Config(c) => Some(c.string_path()),
            Node::ConfigDeclaration(c) => Some(c.string_path()),
            Node::DataSet(d) => Some(d.string_path()),
            Node::MiddlewareDeclaration(m) => Some(m.string_path()),
            Node::HandlerGroupDeclaration(h) => Some(h.string_path()),
            Node::InterfaceDeclaration(i) => Some(i.string_path()),
            Node::Namespace(n) => Some(n.string_path()),
            Node::DecoratorDeclaration(d) => Some(d.string_path()),
            Node::PipelineItemDeclaration(p) => Some(p.string_path()),
            Node::StructDeclaration(s) => Some(s.string_path()),
            _ => None,
        }
    }

    pub fn str_path(&self) -> Option<Vec<&str>> {
        match self {
            Node::Constant(c) => Some(c.str_path()),
            Node::Enum(e) => Some(e.str_path()),
            Node::Model(m) => Some(m.str_path()),
            Node::Config(c) => Some(c.str_path()),
            Node::ConfigDeclaration(c) => Some(c.str_path()),
            Node::DataSet(d) => Some(d.str_path()),
            Node::MiddlewareDeclaration(m) => Some(m.str_path()),
            Node::HandlerGroupDeclaration(h) => Some(h.str_path()),
            Node::InterfaceDeclaration(i) => Some(i.str_path()),
            Node::Namespace(n) => Some(n.str_path()),
            Node::DecoratorDeclaration(d) => Some(d.str_path()),
            Node::PipelineItemDeclaration(p) => Some(p.str_path()),
            Node::StructDeclaration(s) => Some(s.str_path()),
            _ => None,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Node::Constant(c) => Some(c.identifier().name()),
            Node::Enum(e) => Some(e.identifier().name()),
            Node::Model(m) => Some(m.identifier().name()),
            Node::Config(c) => Some(c.name()),
            Node::ConfigDeclaration(c) => Some(c.identifier().name()),
            Node::DataSet(d) => Some(d.identifier().name()),
            Node::MiddlewareDeclaration(m) => Some(m.identifier().name()),
            Node::HandlerGroupDeclaration(a) => Some(a.identifier().name()),
            Node::InterfaceDeclaration(i) => Some(i.identifier().name()),
            Node::Namespace(n) => Some(n.identifier().name()),
            Node::DecoratorDeclaration(d) => Some(d.identifier().name()),
            Node::PipelineItemDeclaration(p) => Some(p.identifier().name()),
            Node::StructDeclaration(s) => Some(s.identifier().name()),
            _ => None,
        }
    }
}

impl Display for Node {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.as_dyn_node_trait(), f)
    }
}

impl Identifiable for Node {
    fn path(&self) -> &Vec<usize> {
        self.as_dyn_node_trait().path()
    }

    fn source_id(&self) -> usize {
        self.as_dyn_node_trait().source_id()
    }

    fn id(&self) -> usize {
        self.as_dyn_node_trait().id()
    }
}

impl NodeTrait for Node {
    fn span(&self) -> Span {
        self.as_dyn_node_trait().span()
    }

    fn children(&self) -> Option<&BTreeMap<usize, Node>> {
        self.as_dyn_node_trait().children()
    }

    fn has_children(&self) -> bool {
        self.as_dyn_node_trait().has_children()
    }

    fn child(&self, id: usize) -> Option<&Node> {
        self.as_dyn_node_trait().child(id)
    }
}

impl Write for Node {
    fn write(&self, writer: &mut Writer) {
        self.as_dyn_node_trait().write(writer)
    }

    fn write_output_with_default_writer(&self) -> String {
        self.as_dyn_node_trait().write_output_with_default_writer()
    }

    fn prefer_whitespace_before(&self) -> bool {
        self.as_dyn_node_trait().prefer_whitespace_before()
    }

    fn prefer_whitespace_after(&self) -> bool {
        self.as_dyn_node_trait().prefer_whitespace_after()
    }

    fn prefer_always_no_whitespace_before(&self) -> bool {
        self.as_dyn_node_trait().prefer_always_no_whitespace_before()
    }

    fn always_start_on_new_line(&self) -> bool {
        self.as_dyn_node_trait().always_start_on_new_line()
    }

    fn always_end_on_new_line(&self) -> bool {
        self.as_dyn_node_trait().always_end_on_new_line()
    }

    fn is_block_start(&self) -> bool {
        self.as_dyn_node_trait().is_block_start()
    }

    fn is_block_end(&self) -> bool {
        self.as_dyn_node_trait().is_block_end()
    }

    fn is_block_element_delimiter(&self) -> bool {
        self.as_dyn_node_trait().is_block_element_delimiter()
    }

    fn is_block_level_element(&self) -> bool {
        self.as_dyn_node_trait().is_block_level_element()
    }

    fn wrap(&self, content: &str, available_length: usize) -> String {
        self.as_dyn_node_trait().wrap(content, available_length)
    }
}