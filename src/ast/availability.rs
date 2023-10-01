static MONGO: u32 = 1;
static MYSQL: u32 = 1 << 1;
static POSTGRES: u32 = 1 << 2;
static SQLITE: u32 = 1 << 3;
static SQL: u32 = MYSQL | POSTGRES | SQLITE;
static ALL: u32 = SQL | MONGO;

#[repr(transparent)]
#[derive(Debug, Copy)]
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

    pub(crate) fn contains(&self, user: Availability) -> bool {
        self.0 & user.0 != 0
    }
}

impl Default for Availability {

    fn default() -> Self {
        Self(ALL)
    }
}