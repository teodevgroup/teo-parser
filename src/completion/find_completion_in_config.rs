use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::config_item::ConfigItem;
use crate::ast::info_provider::InfoProvider;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::completion_item_from_field;

pub(super) fn find_completion_in_config(schema: &Schema, source: &Source, config: &Config, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for item in &config.items {
        if item.span.contains_line_col(line_col) {
            return find_completion_in_config_item(schema, source, item, line_col);
        }
    }
    vec![]
}

fn find_completion_in_config_item(schema: &Schema, source: &Source, item: &ConfigItem, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if item.identifier.span.contains_line_col(line_col) {
        collect_config_declaration_item_names(schema, item.identifier.name(), item.availability())
    } else if item.expression.span().contains_line_col(line_col) {
        vec![]
    }
}

fn collect_config_declaration_item_names(schema: &Schema, config_name: &str, availability: Availability) -> Vec<CompletionItem> {
    let Some(config_declaration) = schema.find_config_declaration_by_name(config_name, availability) else {
        vec![]
    };
    config_declaration.fields.iter().map(|f| completion_item_from_field(f)).collect()
}