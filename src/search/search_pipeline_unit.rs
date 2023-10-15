use crate::ast::argument_list::ArgumentList;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;

pub(crate) fn search_pipeline_unit<HAL, HI, OUTPUT>(
    schema: &Schema,
    source: &Source,
    unit: &Unit,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    handle_argument_list: HAL,
    handle_identifier: HI,
    default: OUTPUT,
) -> OUTPUT where
    HAL: Fn(&ArgumentList, &Vec<usize>) -> OUTPUT,
    HI: Fn(&Vec<usize>) -> OUTPUT,
{
    default
}