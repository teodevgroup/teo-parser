use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::ast::argument_list::ArgumentList;
use crate::ast::arith_expr::ArithExpr;
use crate::ast::bracket_expression::BracketExpression;
use crate::ast::empty_dot::EmptyDot;
use crate::ast::empty_pipeline::EmptyPipeline;
use crate::ast::group::Group;
use crate::ast::pipeline::Pipeline;
use crate::ast::identifier::Identifier;
use crate::ast::int_subscript::IntSubscript;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
use crate::ast::named_expression::NamedExpression;
use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::ast::subscript::Subscript;
use crate::ast::unit::Unit;
use crate::format::Writer;
use crate::traits::identifiable::Identifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::{Resolve, ResolveAndClone};
use crate::traits::write::Write;
use crate::expr::ExprInfo;

#[derive(Debug)]
pub enum ExpressionKind {
    Group(Group),
    ArithExpr(ArithExpr),
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
    ArgumentList(ArgumentList),
    Subscript(Subscript),
    IntSubscript(IntSubscript),
    Unit(Unit),
    Pipeline(Pipeline),
    EmptyPipeline(EmptyPipeline),
    NamedExpression(NamedExpression),
    BracketExpression(BracketExpression),
}

impl ExpressionKind {

    pub fn as_dyn_node_trait(&self) -> &dyn NodeTrait {
        match self {
            ExpressionKind::Group(n) => n,
            ExpressionKind::ArithExpr(n) => n,
            ExpressionKind::NumericLiteral(n) => n,
            ExpressionKind::StringLiteral(n) => n,
            ExpressionKind::RegexLiteral(n) => n,
            ExpressionKind::BoolLiteral(n) => n,
            ExpressionKind::NullLiteral(n) => n,
            ExpressionKind::EnumVariantLiteral(n) => n,
            ExpressionKind::TupleLiteral(n) => n,
            ExpressionKind::ArrayLiteral(n) => n,
            ExpressionKind::DictionaryLiteral(n) => n,
            ExpressionKind::Identifier(n) => n,
            ExpressionKind::ArgumentList(n) => n,
            ExpressionKind::Subscript(n) => n,
            ExpressionKind::IntSubscript(n) => n,
            ExpressionKind::Unit(n) => n,
            ExpressionKind::Pipeline(n) => n,
            ExpressionKind::EmptyPipeline(n) => n,
            ExpressionKind::NamedExpression(n) => n,
            ExpressionKind::BracketExpression(n) => n,
        }
    }

    pub fn as_numeric_literal(&self) -> Option<&NumericLiteral> {
        match self {
            ExpressionKind::NumericLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_numeric_literal(&self) -> bool {
        self.as_numeric_literal().is_some()
    }

    pub fn as_string_literal(&self) -> Option<&StringLiteral> {
        match self {
            ExpressionKind::StringLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_string_literal(&self) -> bool {
        self.as_string_literal().is_some()
    }

    pub fn as_regex_literal(&self) -> Option<&RegexLiteral> {
        match self {
            ExpressionKind::RegexLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_regex_literal(&self) -> bool {
        self.as_regex_literal().is_some()
    }

    pub fn as_bool_literal(&self) -> Option<&BoolLiteral> {
        match self {
            ExpressionKind::BoolLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_bool_literal(&self) -> bool {
        self.as_bool_literal().is_some()
    }

    pub fn as_null_literal(&self) -> Option<&NullLiteral> {
        match self {
            ExpressionKind::NullLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_null_literal(&self) -> bool {
        self.as_null_literal().is_some()
    }

    pub fn as_enum_variant_literal(&self) -> Option<&EnumVariantLiteral> {
        match self {
            ExpressionKind::EnumVariantLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_enum_variant_literal(&self) -> bool {
        self.as_enum_variant_literal().is_some()
    }

    pub fn as_tuple(&self) -> Option<&TupleLiteral> {
        match self {
            ExpressionKind::TupleLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_array_literal(&self) -> Option<&ArrayLiteral> {
        match self {
            ExpressionKind::ArrayLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_array_literal(&self) -> bool {
        self.as_array_literal().is_some()
    }

    pub fn as_dictionary(&self) -> Option<&DictionaryLiteral> {
        match self {
            ExpressionKind::DictionaryLiteral(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_identifier(&self) -> Option<&Identifier> {
        match self {
            ExpressionKind::Identifier(i) => Some(i),
            _ => None,
        }
    }

    pub fn is_identifier(&self) -> bool {
        self.as_identifier().is_some()
    }

    pub fn is_unit(&self) -> bool {
        self.as_unit().is_some()
    }

    pub fn as_unit(&self) -> Option<&Unit> {
        match self {
            ExpressionKind::Unit(u) => Some(u),
            _ => None,
        }
    }

    pub fn as_argument_list(&self) -> Option<&ArgumentList> {
        match self {
            ExpressionKind::ArgumentList(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_subscript(&self) -> Option<&Subscript> {
        match self {
            ExpressionKind::Subscript(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_pipeline(&self) -> Option<&Pipeline> {
        match self {
            ExpressionKind::Pipeline(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_arith_expr(&self) -> Option<&ArithExpr> {
        match self {
            ExpressionKind::ArithExpr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_named_expression(&self) -> Option<&NamedExpression> {
        match self {
            ExpressionKind::NamedExpression(p) => Some(p),
            _ => None,
        }
    }

    pub fn as_bracket_expression(&self) -> Option<&BracketExpression> {
        match self {
            ExpressionKind::BracketExpression(p) => Some(p),
            _ => None,
        }
    }

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        match self {
            ExpressionKind::ArithExpr(a) => a.unwrap_enumerable_enum_member_strings(),
            ExpressionKind::Unit(u) => u.unwrap_enumerable_enum_member_strings(),
            ExpressionKind::EnumVariantLiteral(e) => e.unwrap_enumerable_enum_member_strings(),
            ExpressionKind::ArrayLiteral(a) => a.unwrap_enumerable_enum_member_strings(),
            _ => None,
        }
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        match self {
            ExpressionKind::ArithExpr(a) => a.unwrap_enumerable_enum_member_string(),
            ExpressionKind::Unit(u) => u.unwrap_enumerable_enum_member_string(),
            ExpressionKind::EnumVariantLiteral(e) => e.unwrap_enumerable_enum_member_string(),
            ExpressionKind::ArrayLiteral(a) => a.unwrap_enumerable_enum_member_string(),
            _ => None,
        }
    }
}

impl Identifiable for ExpressionKind {
    fn path(&self) -> &Vec<usize> {
        self.as_dyn_node_trait().path()
    }
}

impl NodeTrait for ExpressionKind {

    fn span(&self) -> Span {
        self.as_dyn_node_trait().span()
    }

    fn children(&self) -> Option<&BTreeMap<usize, Node>> {
        self.as_dyn_node_trait().children()
    }
}

impl Display for ExpressionKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.as_dyn_node_trait(), f)
    }
}

#[derive(Debug)]
pub struct Expression {
    pub kind: ExpressionKind,
    pub resolved: RefCell<Option<ExprInfo>>,
}

impl Expression {

    pub fn new(kind: ExpressionKind) -> Self {
        Self { kind, resolved: RefCell::new(None) }
    }

    pub fn is_single_identifier(&self) -> bool {
        if self.kind.is_identifier() {
            return true;
        }
        if let Some(arith_expr) = self.kind.as_arith_expr() {
            return match arith_expr {
                ArithExpr::Expression(e) => e.is_single_identifier(),
                _ => false,
            };
        }
        if let Some(unit) = self.kind.as_unit() {
            return if unit.expressions().count() == 1 {
                 unit.expression_at(0).unwrap().is_single_identifier() && unit.empty_dot().is_none()
            } else {
                false
            };
        }
        false
    }

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        self.kind.unwrap_enumerable_enum_member_strings()
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        self.kind.unwrap_enumerable_enum_member_string()
    }

    pub fn named_key_without_resolving(&self) -> Option<&str> {
        match &self.kind {
            ExpressionKind::StringLiteral(s) => Some(s.value.as_str()),
            ExpressionKind::Identifier(i) => Some(i.name()),
            _ => None,
        }
    }
}

impl Display for Expression {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.kind, f)
    }
}

impl Identifiable for Expression {

    fn path(&self) -> &Vec<usize> {
        self.kind.path()
    }
}

impl NodeTrait for Expression {
    fn span(&self) -> Span {
        self.kind.span()
    }

    fn children(&self) -> Option<&BTreeMap<usize, Node>> {
        self.kind.children()
    }
}

impl Resolve<ExprInfo> for Expression {
    fn resolved_ref_cell(&self) -> &RefCell<Option<ExprInfo>> {
        &self.resolved
    }
}

impl Write for ExpressionKind {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        self.as_dyn_node_trait().write(writer);
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

impl Write for Expression {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        self.kind.as_dyn_node_trait().write(writer);
    }

    fn write_output_with_default_writer(&self) -> String {
        self.kind.as_dyn_node_trait().write_output_with_default_writer()
    }

    fn prefer_whitespace_before(&self) -> bool {
        self.kind.as_dyn_node_trait().prefer_whitespace_before()
    }

    fn prefer_whitespace_after(&self) -> bool {
        self.kind.as_dyn_node_trait().prefer_whitespace_after()
    }

    fn prefer_always_no_whitespace_before(&self) -> bool {
        self.kind.as_dyn_node_trait().prefer_always_no_whitespace_before()
    }

    fn always_start_on_new_line(&self) -> bool {
        self.kind.as_dyn_node_trait().always_start_on_new_line()
    }

    fn always_end_on_new_line(&self) -> bool {
        self.kind.as_dyn_node_trait().always_end_on_new_line()
    }

    fn is_block_start(&self) -> bool {
        self.kind.as_dyn_node_trait().is_block_start()
    }

    fn is_block_end(&self) -> bool {
        self.kind.as_dyn_node_trait().is_block_end()
    }

    fn is_block_element_delimiter(&self) -> bool {
        self.kind.as_dyn_node_trait().is_block_element_delimiter()
    }

    fn is_block_level_element(&self) -> bool {
        self.kind.as_dyn_node_trait().is_block_level_element()
    }

    fn wrap(&self, content: &str, available_length: usize) -> String {
        self.kind.as_dyn_node_trait().wrap(content, available_length)
    }
}

impl<'a> TryFrom<&'a Node> for &'a Expression {
    type Error = &'static str;

    fn try_from(value: &'a Node) -> Result<Self, Self::Error> {
        match value {
            Node::Expression(n) => Ok(n),
            _ => Err("convert failed"),
        }
    }
}

impl From<Expression> for Node {
    fn from(value: Expression) -> Self {
        Self::Expression(value)
    }
}

impl ResolveAndClone<ExprInfo> for Expression { }