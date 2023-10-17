use std::fmt::{Display, Formatter};

static MONGO: u32 = 1;
static MYSQL: u32 = 1 << 1;
static POSTGRES: u32 = 1 << 2;
static SQLITE: u32 = 1 << 3;
static SQL: u32 = MYSQL | POSTGRES | SQLITE;
static ALL: u32 = SQL | MONGO;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Availability(u32);

impl Availability {

    pub(crate) fn mongo() -> Self {
        Self(MONGO)
    }

    pub(crate) fn sql() -> Self {
        Self(SQL)
    }

    pub(crate) fn mysql() -> Self {
        Self(MYSQL)
    }

    pub(crate) fn postgres() -> Self {
        Self(POSTGRES)
    }

    pub(crate) fn sqlite() -> Self {
        Self(SQLITE)
    }

    pub(crate) fn none() -> Self { Self(0) }

    pub(crate) fn contains(&self, user: Availability) -> bool {
        self.0 & user.0 != 0
    }

    pub(crate) fn is_none(&self) -> bool {
        self.0 == 0
    }
}

impl Default for Availability {

    fn default() -> Self {
        Self(ALL)
    }
}

impl Display for Availability {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut to_join = vec![];
        if self.0 & MYSQL > 0 {
            to_join.push("mysql");
        }
        if self.0 & POSTGRES > 0 {
            to_join.push("postgres");
        }
        if self.0 & SQLITE > 0 {
            to_join.push("sqlite");
        }
        if self.0 & MONGO > 0 {
            to_join.push("mongo");
        }
        if to_join.is_empty() {
            f.write_str(&"none")
        } else {
            f.write_str(&to_join.join(" | "))
        }
    }
}