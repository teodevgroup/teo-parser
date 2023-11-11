use crate::availability::Availability;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_availability_flag(pair: Pair<'_>, context: &mut ParserContext) {
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => {
                match current.as_str() {
                    "noDatabase" => {
                        let flag = Availability::no_database();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    }
                    "database" => {
                        let flag = Availability::database();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    }
                    "mongo" => {
                        let flag = Availability::mongo();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    },
                    "sql" => {
                        let flag = Availability::sql();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    },
                    "mysql" => {
                        let flag = Availability::mysql();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    },
                    "postgres" => {
                        let flag = Availability::postgres();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    },
                    "sqlite" => {
                        let flag = Availability::sqlite();
                        let result = context.push_availability_flag(flag);
                        if result.is_none() {
                            context.insert_error(parse_span(&current), "unreachable availability flag");
                        }
                    },
                    _ => {
                        context.insert_error(parse_span(&current), "unknown availability flag");
                        context.push_availability_flag(Availability::none());
                    }
                }
            }
            _ => (),
        }
    }
}