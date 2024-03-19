use std::ops::{BitAnd, BitOr, BitXor, Not};
use bigdecimal::Zero;
use serde::Serialize;
use teo_result::Result;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OptionVariant {
    pub value: i32,
    pub display: String,
}

impl OptionVariant {

    pub fn into_i32(self) -> i32 {
        self.value
    }

    pub fn normal_not(&self) -> bool {
        self.value.is_zero()
    }
}

impl BitAnd for &OptionVariant {

    type Output = Result<OptionVariant>;

    fn bitand(self, rhs: Self) -> Self::Output {
        Ok(OptionVariant {
            value: self.value & rhs.value,
            display: format!("({} & {})", self.display, rhs.display),
        })
    }
}

impl BitOr for &OptionVariant {

    type Output = Result<OptionVariant>;

    fn bitor(self, rhs: Self) -> Self::Output {
        Ok(OptionVariant {
            value: self.value | rhs.value,
            display: format!("({} | {})", self.display, rhs.display),
        })
    }
}

impl BitXor for &OptionVariant {

    type Output = Result<OptionVariant>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Ok(OptionVariant {
            value: self.value ^ rhs.value,
            display: format!("({} ^ {})", self.display, rhs.display),
        })
    }
}

impl Not for &OptionVariant {

    type Output = OptionVariant;

    fn not(self) -> Self::Output {
        OptionVariant {
            value: self.value.not(),
            display: format!("~{}", self.display),
        }
    }
}
