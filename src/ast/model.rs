use std::cmp::Ordering;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use itertools::Itertools;
use crate::ast::reference::ReferenceType;
use crate::completion::completion::CompletionItem;
use crate::completion::completion_context::CompletionContext;

#[derive(Debug)]
pub struct Model {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) decorators: Vec<Decorator>,
    pub(crate) identifier: Identifier,
    pub(crate) fields: Vec<Field>,
}

impl Model {

    pub(crate) fn new(
        path: Vec<usize>,
        string_path: Vec<String>,
        identifier: Identifier,
        comment: Option<Comment>,
        fields: Vec<Field>,
        decorators: Vec<Decorator>,
        span: Span
    ) -> Self {
        Self {
            path,
            string_path,
            identifier,
            comment,
            fields,
            decorators,
            span,
        }
    }

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    // pub(crate) fn sorted_fields(&self) -> Vec<&Field> {
    //     self.fields.iter().sorted_by(|a, b| if a.resolved().class.is_primitive_field() {
    //         Ordering::Greater
    //     } else if b.resolved().class.is_relation() {
    //         Ordering::Less
    //     } else {
    //         Ordering::Less
    //     }).collect()
    // }

    pub(crate) fn field_named(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name() == key)
    }

    pub(crate) fn find_auto_complete_items<'a>(&'a self, context: &mut CompletionContext<'a>, line_col: (usize, usize)) -> Vec<CompletionItem> {
        for field in &self.fields {
            if field.span.contains_line_col(line_col) {
                return field.find_auto_complete_items(context, line_col);
            }
        }
        for decorator in &self.decorators {
            if decorator.span.contains_line_col(line_col) {
                return decorator.find_auto_complete_items(context, line_col, ReferenceType::ModelDecorator);
            }
        }
        vec![]
    }
}
