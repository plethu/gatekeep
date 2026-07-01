use std::marker::PhantomData;

use sqlx::{
    QueryBuilder,
    types::{
        Uuid,
        time::{Date, OffsetDateTime, PrimitiveDateTime, Time},
    },
};

/// `SQLx` backend supported by gatekeep lowering.
pub trait GatekeepSqlxBackend: Clone + Copy + core::fmt::Debug + Send + Sync + 'static {
    /// `SQLx` database driver for this backend.
    type Database: sqlx::Database;

    /// Database driver represented by this backend.
    const DRIVER: SqlxDriver;

    /// Stable backend name.
    const NAME: &'static str;

    /// Appends one bind placeholder to rendered SQL.
    fn push_placeholder(sql: &mut String, index: usize);

    /// Appends one typed bind value to a `SQLx` query builder.
    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue);

    /// Name of the SQL function that returns the lower of two non-null grades.
    const MIN_FUNCTION: &'static str;

    /// Name of the SQL function that returns the higher of two non-null grades.
    const MAX_FUNCTION: &'static str;

    /// Whether the backend's grade functions return `NULL` when any input is
    /// `NULL`.
    const GRADE_FUNCTION_PROPAGATES_NULL: bool;
}

macro_rules! push_sqlx_bind {
    ($builder:expr, $value:expr) => {
        match $value {
            SqlxValue::Bool(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::I16(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::I32(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::I64(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Text(value) => {
                $builder.push_bind(value.clone());
            }
            SqlxValue::Bytes(value) => {
                $builder.push_bind(value.clone());
            }
            SqlxValue::Uuid(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Date(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Time(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Timestamp(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::TimestampTz(value) => {
                $builder.push_bind(*value);
            }
        }
    };
}

/// Postgres backend marker.
#[cfg(feature = "postgres")]
#[derive(Clone, Copy, Debug)]
pub struct PostgresBackend;

#[cfg(feature = "postgres")]
impl GatekeepSqlxBackend for PostgresBackend {
    type Database = sqlx::Postgres;

    const DRIVER: SqlxDriver = SqlxDriver::Postgres;
    const NAME: &'static str = "postgres";
    const MIN_FUNCTION: &'static str = "LEAST";
    const MAX_FUNCTION: &'static str = "GREATEST";
    const GRADE_FUNCTION_PROPAGATES_NULL: bool = false;

    fn push_placeholder(sql: &mut String, index: usize) {
        sql.push('$');
        sql.push_str(&index.to_string());
    }

    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue) {
        push_sqlx_bind!(builder, value);
    }
}

/// `SQLite` backend marker.
#[cfg(feature = "sqlite")]
#[derive(Clone, Copy, Debug)]
pub struct SqliteBackend;

#[cfg(feature = "sqlite")]
impl GatekeepSqlxBackend for SqliteBackend {
    type Database = sqlx::Sqlite;

    const DRIVER: SqlxDriver = SqlxDriver::Sqlite;
    const NAME: &'static str = "sqlite";
    const MIN_FUNCTION: &'static str = "min";
    const MAX_FUNCTION: &'static str = "max";
    const GRADE_FUNCTION_PROPAGATES_NULL: bool = true;

    fn push_placeholder(sql: &mut String, _index: usize) {
        sql.push('?');
    }

    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue) {
        push_sqlx_bind!(builder, value);
    }
}

/// `MySQL` backend marker.
#[cfg(feature = "mysql")]
#[derive(Clone, Copy, Debug)]
pub struct MySqlBackend;

#[cfg(feature = "mysql")]
impl GatekeepSqlxBackend for MySqlBackend {
    type Database = sqlx::MySql;

    const DRIVER: SqlxDriver = SqlxDriver::MySql;
    const NAME: &'static str = "mysql";
    const MIN_FUNCTION: &'static str = "LEAST";
    const MAX_FUNCTION: &'static str = "GREATEST";
    const GRADE_FUNCTION_PROPAGATES_NULL: bool = true;

    fn push_placeholder(sql: &mut String, _index: usize) {
        sql.push('?');
    }

    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue) {
        push_sqlx_bind!(builder, value);
    }
}

/// Supported `SQLx` database driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqlxDriver {
    /// Postgres `SQLx` driver.
    Postgres,
    /// `SQLite` `SQLx` driver.
    Sqlite,
    /// `MySQL` `SQLx` driver.
    MySql,
}

impl SqlxDriver {
    /// Stable driver name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Sqlite => "sqlite",
            Self::MySql => "mysql",
        }
    }

    /// Whether this crate was compiled with the matching backend feature.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        match self {
            Self::Postgres => cfg!(feature = "postgres"),
            Self::Sqlite => cfg!(feature = "sqlite"),
            Self::MySql => cfg!(feature = "mysql"),
        }
    }
}

/// Database driver configuration error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SqlxDriverError {
    /// The URL scheme is not recognized as a `SQLx` database driver.
    #[error("unsupported SQLx database URL scheme {scheme:?}")]
    UnsupportedUrlScheme {
        /// URL scheme, if one could be parsed.
        scheme: Option<String>,
    },

    /// The URL selects a driver whose feature was not enabled.
    #[error("SQLx driver {driver} is not enabled for gatekeep-sqlx")]
    DriverNotEnabled {
        /// Driver inferred from the URL.
        driver: &'static str,
    },

    /// The configured driver does not match the selected backend.
    #[error("SQLx backend mismatch: expected {expected}, found {actual}")]
    BackendMismatch {
        /// Backend expected by the selected lowerer.
        expected: &'static str,
        /// Driver inferred from runtime configuration.
        actual: &'static str,
    },
}

/// Infers the `SQLx` driver from a database URL or `SQLx`-style `SQLite` memory URL.
///
/// # Errors
///
/// Returns [`SqlxDriverError`] when the URL scheme is unsupported or when the
/// inferred driver was not enabled at compile time.
pub fn infer_enabled_driver_from_url(database_url: &str) -> Result<SqlxDriver, SqlxDriverError> {
    let driver = infer_driver_from_url(database_url)?;
    if driver.is_enabled() {
        Ok(driver)
    } else {
        Err(SqlxDriverError::DriverNotEnabled {
            driver: driver.name(),
        })
    }
}

/// Validates that a database URL matches a selected backend.
///
/// # Errors
///
/// Returns [`SqlxDriverError`] when the URL is unsupported, names a disabled
/// driver, or names a different driver from `B`.
pub fn validate_database_url_for_backend<B>(database_url: &str) -> Result<(), SqlxDriverError>
where
    B: GatekeepSqlxBackend,
{
    let actual = infer_enabled_driver_from_url(database_url)?;
    if actual == B::DRIVER {
        Ok(())
    } else {
        Err(SqlxDriverError::BackendMismatch {
            expected: B::NAME,
            actual: actual.name(),
        })
    }
}

fn infer_driver_from_url(database_url: &str) -> Result<SqlxDriver, SqlxDriverError> {
    if database_url.starts_with("sqlite:") {
        return Ok(SqlxDriver::Sqlite);
    }

    let Some((scheme, _rest)) = database_url.split_once(':') else {
        return Err(SqlxDriverError::UnsupportedUrlScheme { scheme: None });
    };

    match scheme {
        "postgres" | "postgresql" => Ok(SqlxDriver::Postgres),
        "mysql" | "mariadb" => Ok(SqlxDriver::MySql),
        "sqlite" => Ok(SqlxDriver::Sqlite),
        other => Err(SqlxDriverError::UnsupportedUrlScheme {
            scheme: Some(other.to_owned()),
        }),
    }
}

/// Scalar value carried by a lowered SQL fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqlxValue {
    /// Boolean bind value.
    Bool(bool),
    /// Signed 16-bit integer bind value.
    I16(i16),
    /// Signed 32-bit integer bind value.
    I32(i32),
    /// Signed 64-bit integer bind value.
    I64(i64),
    /// Text bind value.
    Text(String),
    /// Binary bind value.
    Bytes(Vec<u8>),
    /// UUID bind value.
    Uuid(Uuid),
    /// Date bind value.
    Date(Date),
    /// Time bind value.
    Time(Time),
    /// Timestamp without time zone bind value.
    Timestamp(PrimitiveDateTime),
    /// Timestamp with time zone bind value.
    TimestampTz(OffsetDateTime),
}

macro_rules! impl_sqlx_value_from {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for SqlxValue {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_sqlx_value_from!(bool, Bool);
impl_sqlx_value_from!(i16, I16);
impl_sqlx_value_from!(i32, I32);
impl_sqlx_value_from!(i64, I64);
impl_sqlx_value_from!(String, Text);
impl_sqlx_value_from!(Vec<u8>, Bytes);
impl_sqlx_value_from!(Uuid, Uuid);
impl_sqlx_value_from!(Date, Date);
impl_sqlx_value_from!(Time, Time);
impl_sqlx_value_from!(PrimitiveDateTime, Timestamp);
impl_sqlx_value_from!(OffsetDateTime, TimestampTz);

impl From<&str> for SqlxValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<&[u8]> for SqlxValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SqlPart {
    Text(String),
    Bind(SqlxValue),
}

/// Trusted SQL plus ordered bind values for one `SQLx` backend.
#[derive(Debug, PartialEq, Eq)]
pub struct SqlxFragment<B> {
    parts: Vec<SqlPart>,
    backend: PhantomData<fn() -> B>,
}

impl<B> Clone for SqlxFragment<B> {
    fn clone(&self) -> Self {
        Self {
            parts: self.parts.clone(),
            backend: PhantomData,
        }
    }
}

impl<B> Default for SqlxFragment<B> {
    fn default() -> Self {
        Self {
            parts: Vec::new(),
            backend: PhantomData,
        }
    }
}

impl<B> SqlxFragment<B> {
    /// Builds a fragment from SQL owned by the application.
    ///
    /// Callers must not pass user-supplied text here. Dynamic values belong in
    /// bind fragments built with [`Self::bind`].
    #[must_use]
    pub fn trusted(sql: impl Into<String>) -> Self {
        let sql = sql.into();
        if sql.is_empty() {
            Self::default()
        } else {
            Self {
                parts: vec![SqlPart::Text(sql)],
                backend: PhantomData,
            }
        }
    }

    /// Builds a bind fragment from a supported `SQLx` scalar value.
    #[must_use]
    pub fn bind(value: impl Into<SqlxValue>) -> Self {
        Self {
            parts: vec![SqlPart::Bind(value.into())],
            backend: PhantomData,
        }
    }

    /// Returns the ordered bind values.
    pub fn binds(&self) -> impl Iterator<Item = &SqlxValue> {
        self.parts.iter().filter_map(|part| match part {
            SqlPart::Text(_) => None,
            SqlPart::Bind(value) => Some(value),
        })
    }

    /// Appends another fragment to this one.
    pub fn push_fragment(&mut self, fragment: Self) {
        self.parts.extend(fragment.parts);
    }

    pub(crate) fn push_sql(&mut self, sql: impl Into<String>) {
        let sql = sql.into();
        if !sql.is_empty() {
            self.parts.push(SqlPart::Text(sql));
        }
    }

    #[must_use]
    pub(crate) fn wrapped(self) -> Self {
        let mut fragment = Self::trusted("(");
        fragment.push_fragment(self);
        fragment.push_sql(")");
        fragment
    }

    #[must_use]
    pub(crate) fn unary(prefix: &str, inner: Self) -> Self {
        let mut fragment = Self::trusted(prefix);
        fragment.push_fragment(inner.wrapped());
        fragment
    }

    #[must_use]
    pub(crate) fn binary(separator: &str, fragments: impl IntoIterator<Item = Self>) -> Self {
        let mut iter = fragments.into_iter();
        let Some(first) = iter.next() else {
            return Self::trusted("FALSE");
        };

        let mut fragment = first.wrapped();
        for next in iter {
            fragment.push_sql(separator);
            fragment.push_fragment(next.wrapped());
        }
        fragment
    }

    #[must_use]
    pub(crate) fn function(name: &str, fragments: impl IntoIterator<Item = Self>) -> Self {
        let mut fragment = Self::trusted(name);
        fragment.push_sql("(");

        let mut iter = fragments.into_iter();
        if let Some(first) = iter.next() {
            fragment.push_fragment(first);
            for next in iter {
                fragment.push_sql(", ");
                fragment.push_fragment(next);
            }
        }

        fragment.push_sql(")");
        fragment
    }
}

impl<B> SqlxFragment<B>
where
    B: GatekeepSqlxBackend,
{
    /// Converts the fragment to SQL with this backend's placeholder syntax.
    #[must_use]
    pub fn to_sql(&self) -> String {
        let mut sql = String::new();
        let mut placeholders = 0usize;

        for part in &self.parts {
            match part {
                SqlPart::Text(text) => sql.push_str(text),
                SqlPart::Bind(_) => {
                    placeholders += 1;
                    B::push_placeholder(&mut sql, placeholders);
                }
            }
        }
        sql
    }

    /// Appends this fragment to a `SQLx` query builder.
    pub fn push_to(&self, builder: &mut QueryBuilder<B::Database>) {
        for part in &self.parts {
            match part {
                SqlPart::Text(text) => {
                    builder.push(text);
                }
                SqlPart::Bind(value) => B::push_bind(builder, value),
            }
        }
    }
}

/// Postgres scalar value carried by a lowered SQL fragment.
pub type PgValue = SqlxValue;

/// Trusted Postgres SQL plus ordered bind values.
#[cfg(feature = "postgres")]
pub type PgFragment = SqlxFragment<PostgresBackend>;

#[cfg(feature = "postgres")]
impl SqlxFragment<PostgresBackend> {
    /// Converts the fragment to Postgres placeholders (`$1`, `$2`, ...).
    #[must_use]
    pub fn to_postgres_sql(&self) -> String {
        self.to_sql()
    }
}
