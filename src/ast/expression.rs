use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use teo_teon::Value;
use crate::ast::argument_list::ArgumentList;
use crate::ast::arith::ArithExpr;
use crate::ast::group::Group;
use crate::ast::pipeline::Pipeline;
use crate::ast::identifier::Identifier;
use crate::ast::int_subscript::IntSubscript;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
use crate::ast::span::Span;
use crate::ast::subscript::Subscript;
use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;

#[derive(Debug)]
pub struct Negation {
    pub expression: Box<Expression>,
    pub span: Span,
}

impl Display for Negation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("-")?;
        Display::fmt(self.expression.as_ref(), f)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BitwiseNegation {
    pub expression: Box<Expression>,
    pub span: Span,
}

impl Display for BitwiseNegation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("~")?;
        Display::fmt(self.expression.as_ref(), f)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NullishCoalescing {
    pub expressions: Vec<Expression>,
    pub span: Span,
}

impl Display for NullishCoalescing {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let len = self.expressions.len();
        for (index, expression) in self.expressions.iter().enumerate() {
            Display::fmt(expression, f)?;
            if index != len - 1 {
                f.write_str(" ?? ")?;
            }
        }
        Ok(())
    }
}

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
}

impl ExpressionKind {

    pub fn span(&self) -> Span {
        match self {
            ExpressionKind::Group(e) => e.span,
            ExpressionKind::ArithExpr(e) => e.span(),
            ExpressionKind::NumericLiteral(e) => e.span,
            ExpressionKind::StringLiteral(e) => e.span,
            ExpressionKind::RegexLiteral(e) => e.span,
            ExpressionKind::BoolLiteral(e) => e.span,
            ExpressionKind::NullLiteral(e) => e.span,
            ExpressionKind::EnumVariantLiteral(e) => e.span,
            ExpressionKind::TupleLiteral(e) => e.span,
            ExpressionKind::ArrayLiteral(e) => e.span,
            ExpressionKind::DictionaryLiteral(e) => e.span,
            ExpressionKind::Identifier(e) => e.span,
            ExpressionKind::ArgumentList(e) => e.span,
            ExpressionKind::Subscript(e) => e.span,
            ExpressionKind::IntSubscript(i) => i.span,
            ExpressionKind::Unit(e) => e.span,
            ExpressionKind::Pipeline(e) => e.span,
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

impl Display for ExpressionKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpressionKind::Group(g) => Display::fmt(g, f),
            ExpressionKind::NumericLiteral(e) => Display::fmt(e, f),
            ExpressionKind::StringLiteral(s) => Display::fmt(s, f),
            ExpressionKind::RegexLiteral(r) => Display::fmt(r, f),
            ExpressionKind::BoolLiteral(b) => Display::fmt(b, f),
            ExpressionKind::NullLiteral(n) => Display::fmt(n, f),
            ExpressionKind::EnumVariantLiteral(e) => Display::fmt(e, f),
            ExpressionKind::TupleLiteral(t) => Display::fmt(t, f),
            ExpressionKind::ArrayLiteral(a) => Display::fmt(a, f),
            ExpressionKind::DictionaryLiteral(d) => Display::fmt(d, f),
            ExpressionKind::Identifier(i) => Display::fmt(i, f),
            ExpressionKind::ArgumentList(a) => Display::fmt(a, f),
            ExpressionKind::Subscript(s) => Display::fmt(s, f),
            ExpressionKind::IntSubscript(i) => Display::fmt(i, f),
            ExpressionKind::Unit(u) => Display::fmt(u, f),
            ExpressionKind::Pipeline(p) => Display::fmt(p, f),
            ExpressionKind::ArithExpr(a) => Display::fmt(a, f),
        }
    }
}

#[derive(Debug)]
pub struct Expression {
    pub kind: ExpressionKind,
    pub resolved: RefCell<Option<TypeAndValue>>,
}

impl Expression {

    pub fn new(kind: ExpressionKind) -> Self {
        Self { kind, resolved: RefCell::new(None) }
    }

    pub fn span(&self) -> Span {
        self.kind.span()
    }

    pub fn resolve(&self, resolved: TypeAndValue) -> TypeAndValue {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved.clone());
        resolved
    }

    pub fn resolved(&self) -> &TypeAndValue {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        self.kind.unwrap_enumerable_enum_member_strings()
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        self.kind.unwrap_enumerable_enum_member_string()
    }
}

impl Display for Expression {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.kind, f)
    }
}

#[derive(Debug, Clone)]
pub struct TypeAndValue {
    pub r#type: Type,
    pub value: Option<Value>,
}

impl TypeAndValue {

    pub fn new(r#type: Type, value: Option<Value>) -> Self {
        Self { r#type, value }
    }

    pub fn r#type(&self) -> &Type {
        &self.r#type
    }

    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn is_undetermined(&self) -> bool {
        self.r#type().is_undetermined()
    }

    pub fn undetermined() -> Self {
        TypeAndValue {
            r#type: Type::Undetermined,
            value: None,
        }
    }

    pub fn with_type(&self, new_type: Type) -> Self {
        TypeAndValue {
            r#type: new_type,
            value: self.value.clone()
        }
    }

    pub fn with_value(&self, new_value: Option<Value>) -> Self {
        TypeAndValue {
            r#type: self.r#type.clone(),
            value: new_value,
        }
    }

    pub fn type_only(t: Type) -> Self {
        TypeAndValue {
            r#type: t,
            value: None
        }
    }
}