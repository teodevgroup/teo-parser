use crate::ast::config::Config;
use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::interface::InterfaceItem;
use crate::ast::interface_type::InterfaceType;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_interface_declaration(pair: Pair<'_>, context: &mut ParserContext) -> Config {
    let span = parse_span(&pair);
    let mut identifier = None;
    let mut name: Option<InterfaceType> = None;
    let mut extends: Vec<InterfaceType> = vec![];
    let mut items: Vec<InterfaceItem> = vec![];
    let span = parse_span(&pair);
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::interface_type => {
                let interface_type = parser_interface_type(current, context);
                if name.is_some() {
                    extends.push(interface_type);
                } else {
                    name = Some(interface_type);
                }
            }
            Rule::interface_item => {
                let interface_item_decl = parse_interface_item_declaration(current, context);
                items.push(interface_item_decl);
            }
            _ => (),
        }
    }
    Top::InterfaceDeclaration(InterfaceDeclaration {
        id: item_id,
        source_id,
        name: name.unwrap(),
        extends,
        items,
        span,
    })
}