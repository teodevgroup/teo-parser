use std::fmt::{Display, Formatter};

static NO_DATABASE: u32 = 1;
static MONGO: u32 = 1 << 1;
static MYSQL: u32 = 1 << 2;
static POSTGRES: u32 = 1 << 3;
static SQLITE: u32 = 1 << 4;
static DATABASE: u32 = MONGO | MYSQL | POSTGRES | SQLITE;
static SQL: u32 = MYSQL | POSTGRES | SQLITE;
static ALL: u32 = SQL | MONGO;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Availability(u32);

impl Availability {

    pub fn no_database() -> Self {
        Self(NO_DATABASE)
    }

    pub fn none() -> Self {
        Self(0)
    }

    pub fn database() -> Self {
        Self(DATABASE)
    }

    pub fn mongo() -> Self {
        Self(MONGO)
    }

    pub fn sql() -> Self {
        Self(SQL)
    }

    pub fn mysql() -> Self {
        Self(MYSQL)
    }

    pub fn postgres() -> Self {
        Self(POSTGRES)
    }

    pub fn sqlite() -> Self {
        Self(SQLITE)
    }

    pub fn contains(&self, actual: Availability) -> bool {
        self.0 & actual.0 != 0
    }

    pub fn is_none(&self) -> bool {
        self.0 == 0
    }

    pub(crate) fn bi_and(&self, other: Availability) -> Availability {
        Self(self.0 & other.0)
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
        if self.0 & NO_DATABASE > 0 {
            to_join.push("noDatabase");
        }
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