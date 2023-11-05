use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::config_item::ConfigItem;
use crate::ast::info_provider::InfoProvider;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::completion_item_from_field;

pub(super) fn find_completion_in_config(schema: &Schema, source: &Source, config: &Config, line_col: (usize, usize)) -> Vec<CompletionItem> {
    let mut used: Vec<&str> = vec![];
    used.extend(config.items.iter().map(|i| i.identifier.name()));
    used.extend(config.unattached_identifiers.iter().map(|i| i.name()));
    for item in &config.items {
        if item.span.contains_line_col(line_col) {
            return find_completion_in_config_item(schema, item, line_col, &used);
        }
    }
    for unattached_identifier in &config.unattached_identifiers {
        if unattached_identifier.span.contains_line_col(line_col) {
            return collect_config_declaration_item_names(schema, config.keyword.name(), config.availability(), &used)
        }
    }
    vec![]
}

fn find_completion_in_config_item(schema: &Schema, item: &ConfigItem, line_col: (usize, usize), used: &Vec<&str>) -> Vec<CompletionItem> {
    if item.identifier.span.contains_line_col(line_col) {
        collect_config_declaration_item_names(schema, item.identifier.name(), item.availability(), used)
    } else if item.expression.span().contains_line_col(line_col) {
        vec![]
    } else {
        vec![]
    }
}

fn collect_config_declaration_item_names(schema: &Schema, config_name: &str, availability: Availability, used: &Vec<&str>) -> Vec<CompletionItem> {
    let Some(config_declaration) = schema.find_config_declaration_by_name(config_name, availability) else {
        return vec![];
    };
    config_declaration.fields.iter().filter(|f| !used.contains(&f.identifier.name())).map(|f| completion_item_from_field(f)).collect()
}