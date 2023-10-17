use crate::ast::availability::Availability;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_availability_flag(pair: Pair<'_>, context: &mut ParserContext) -> Availability {
    //let span = parse_span(&pair);
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => {
                match current.as_str() {
                    "mongo" => {
                        let flag = Availability::mongo();
                        context.push_availability_flag(flag);
                        return flag;
                    },
                    "sql" => {
                        let flag = Availability::sql();
                        context.push_availability_flag(flag);
                        return flag;
                    },
                    "mysql" => {
                        let flag = Availability::mysql();
                        context.push_availability_flag(flag);
                        return flag;
                    },
                    "postgres" => {
                        let flag = Availability::postgres();
                        context.push_availability_flag(flag);
                        return flag;
                    },
                    "sqlite" => {
                        let flag = Availability::sqlite();
                        context.push_availability_flag(flag);
                        return flag;
                    },
                    _ => {
                        context.insert_error(parse_span(&current), "unknown availability flag");
                        return Availability::default();
                    }
                }
            }
            _ => (),
        }
    }
    return Availability::default();
}