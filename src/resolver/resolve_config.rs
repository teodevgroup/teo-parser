use std::collections::HashSet;
use itertools::Itertools;
use maplit::btreemap;
use crate::ast::config::{Config, ConfigResolved};
use crate::ast::config_item::ConfigItemResolved;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_config<'a>(config: &'a Config, context: &'a ResolverContext<'a>) {
    let availability = context.current_availability();
    config.resolve(ConfigResolved {
        actual_availability: availability
    });
    for item in &config.items {
        item.resolve(ConfigItemResolved {
            actual_availability: availability
        });
    }
    if let Some(config_declaration) = context.schema.find_config_declaration_by_name(config.keyword.name(), availability) {
        let exist_keys: HashSet<&str> = config.items.iter().map(|i| i.identifier.name()).collect();
        let defined_keys: HashSet<&str> = config_declaration.fields.iter().map(|f| f.identifier.name()).collect();
        let differences = exist_keys.difference(&defined_keys);
        // undefined items
        for item_name in differences {
            let item = config.items.iter().find(|i| i.identifier.name() == *item_name).unwrap();
            context.insert_diagnostics_error(item.identifier.span, "ConfigError: undefined config item");
        }
        // duplicated items
        for item in config.items.iter().duplicates_by(|i| i.identifier.name()) {
            context.insert_diagnostics_error(item.identifier.span, "ConfigError: duplicated config item");
        }
        // collect missing
        let mut missing_names = vec![];
        // check each field
        for field in &config_declaration.fields {
            if let Some(item) = config.items.iter().find(|i| i.identifier.name() == field.identifier.name()) {
                resolve_expression(&item.expression, context, field.type_expr.resolved(), &btreemap! {});
                let r#type = item.expression.resolved().r#type();
                if !r#type.is_undetermined() {
                    if !field.type_expr.resolved().test(r#type) {
                        context.insert_diagnostics_error(item.expression.span(), format!("expect {}, found {}", field.type_expr.resolved(), r#type));
                    }
                }
            } else {
                if !field.type_expr.resolved().is_optional() {
                    missing_names.push(field.identifier.name());
                }
            }
        }
        if !missing_names.is_empty() {
            context.insert_diagnostics_error(config.keyword.span, format!("missing required config items: {}", missing_names.join(", ")));
        }
    } else {
        context.insert_diagnostics_error(config.keyword.span, "configuration is undefined");
    }
}